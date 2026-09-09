package backup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"backup/internal/extsort"
	"backup/internal/format"
)

const maximumDataPartRecordBytes = 64 << 10

// Bound decoder read-ahead as well as each record, without imposing a ceiling
// on the complete JSON array. The serialized transaction format is unchanged.
type dataPartRecordReader struct {
	reader io.Reader
	read   int64
	end    int64
}

func (reader *dataPartRecordReader) Read(buffer []byte) (int, error) {
	if reader.read >= reader.end {
		return 0, fmt.Errorf("staged data-part record exceeds %d bytes", maximumDataPartRecordBytes)
	}
	if int64(len(buffer)) > reader.end-reader.read {
		buffer = buffer[:reader.end-reader.read]
	}
	count, err := reader.reader.Read(buffer)
	reader.read += int64(count)
	return count, err
}

func (reader *dataPartRecordReader) bound(offset int64) error {
	if offset > math.MaxInt64-maximumDataPartRecordBytes {
		return fmt.Errorf("staged data-part descriptor is too large")
	}
	reader.end = offset + maximumDataPartRecordBytes
	return nil
}

func marshalDataPart(part stagedDataPart) ([]byte, error) {
	if err := validStagedRelativePath(part.RelativePath); err != nil {
		return nil, fmt.Errorf("invalid staged data path: %w", err)
	}
	if _, err := format.MarshalPackEntry(part.Entry); err != nil {
		return nil, fmt.Errorf("invalid staged data part: %w", err)
	}
	data, err := json.Marshal(part)
	if err != nil {
		return nil, err
	}
	// Reserve space for the array separator and record terminator.
	if len(data) > maximumDataPartRecordBytes-2 {
		return nil, fmt.Errorf("staged data-part record exceeds %d bytes", maximumDataPartRecordBytes)
	}
	return data, nil
}

func walkDataPartRecords(input io.Reader, visit func(uint64, stagedDataPart) error) (uint64, error) {
	bounded := &dataPartRecordReader{reader: input, end: maximumDataPartRecordBytes}
	decoder := json.NewDecoder(bounded)
	decoder.DisallowUnknownFields()
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('[') {
		return 0, fmt.Errorf("staged data parts require a JSON array: %v", err)
	}
	var count uint64
	for {
		if err := bounded.bound(decoder.InputOffset()); err != nil {
			return count, err
		}
		if !decoder.More() {
			break
		}
		if count == uint64(format.DefaultLimits().MaxRecords) {
			return count, fmt.Errorf("staged data-part count exceeds the catalog limit")
		}
		var part stagedDataPart
		if err := decoder.Decode(&part); err != nil {
			return count, fmt.Errorf("decode staged data part %d: %w", count, err)
		}
		if _, err := marshalDataPart(part); err != nil {
			return count, err
		}
		if visit != nil {
			if err := visit(count, part); err != nil {
				return count, err
			}
		}
		count++
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(']') {
		return count, fmt.Errorf("staged data parts lack the closing array delimiter: %v", err)
	}
	if err := bounded.bound(decoder.InputOffset()); err != nil {
		return count, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return count, fmt.Errorf("trailing staged data-part JSON: %v", err)
	}
	return count, nil
}

func (run *runtime) readDataParts(ref stagedFileRef, visit func(uint64, stagedDataPart) error) (uint64, error) {
	if ref == (stagedFileRef{}) {
		return 0, nil
	}
	// Verify the complete reference before any visitor can upload or publish.
	if err := run.validateStagedRef(ref); err != nil {
		return 0, err
	}
	file, err := run.openStaged(ref.RelativePath)
	if err != nil {
		return 0, err
	}
	count, walkErr := walkDataPartRecords(file, visit)
	return count, errors.Join(walkErr, file.Close())
}

func (run *runtime) walkDataParts(txn *transaction, visit func(uint64, stagedDataPart) error) error {
	count, err := run.readDataParts(txn.DataPartsFile, visit)
	if err == nil && count != txn.DataPartCount {
		err = fmt.Errorf("staged data-part count changed")
	}
	return err
}

// Rewrite under a fresh content-addressed name before replacing the control
// record. Append order stays stable because upload cursors use that order.
func (run *runtime) rewriteDataParts(txn *transaction, position uint64, replacement stagedDataPart) error {
	if position > txn.DataPartCount {
		return fmt.Errorf("invalid staged data-part replacement position")
	}
	encoded, err := marshalDataPart(replacement)
	if err != nil {
		return err
	}
	if txn.DataPartsFile.Size > math.MaxInt64-uint64(len(encoded))-4 {
		return fmt.Errorf("staged data-part descriptor size overflows")
	}
	directory := filepath.Join(run.options.transactionFilesPath(), "candidate")
	if err := requireWorkspaceCapacity(directory, txn.DataPartsFile.Size+uint64(len(encoded))+4, 1, run.options.SpaceReserveBytes); err != nil {
		return fmt.Errorf("stage repair descriptors: %w", err)
	}
	file, err := os.CreateTemp(directory, ".data-parts-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
	writer := bufio.NewWriterSize(file, 256<<10)
	if _, err := writer.WriteString("["); err != nil {
		return err
	}
	var count uint64
	emit := func(data []byte) error {
		if count == uint64(format.DefaultLimits().MaxRecords) {
			return fmt.Errorf("staged data-part count exceeds the catalog limit")
		}
		if count != 0 {
			if err := writer.WriteByte(','); err != nil {
				return err
			}
		}
		if _, err := writer.Write(data); err != nil {
			return err
		}
		count++
		return nil
	}
	if err := run.walkDataParts(txn, func(index uint64, part stagedDataPart) error {
		if index == position {
			return emit(encoded)
		}
		data, err := marshalDataPart(part)
		if err != nil {
			return err
		}
		return emit(data)
	}); err != nil {
		return err
	}
	if position == txn.DataPartCount {
		if err := emit(encoded); err != nil {
			return err
		}
	}
	if _, err := writer.WriteString("]\n"); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	relative, err := run.stagedRelativePath(temporary)
	if err != nil {
		return err
	}
	ref, err := run.referenceStagedFile(relative)
	if err != nil {
		return err
	}
	ref.RelativePath = filepath.Join("candidate", "data-parts-"+ref.BLAKE2b+".json")
	destination, err := run.stagedPath(ref.RelativePath)
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	txn.DataPartsFile, txn.DataPartCount = ref, count
	return run.checkpoint("repair-descriptors-staged")
}

// Sorted temporary views bound duplicate detection and catalog matching without
// retaining the cumulative repair descriptors or a second catalog in memory.
func (run *runtime) validateDataPartCatalog(txn *transaction, metadataPaths map[string]bool, walkCatalog func(func(format.PackEntry) error) error, exact bool) error {
	if txn.DataPartCount == 0 {
		if !exact {
			return nil
		}
		return walkCatalog(func(format.PackEntry) error {
			return fmt.Errorf("candidate changes packs without staged data parts")
		})
	}
	if txn.DataPartsFile.Size > math.MaxInt64/4 {
		return fmt.Errorf("repair validation workspace size overflows")
	}
	if err := requireWorkspaceCapacity(run.options.statePath(), txn.DataPartsFile.Size*4, 16, run.options.SpaceReserveBytes); err != nil {
		return fmt.Errorf("validate repair descriptors: %w", err)
	}
	workspace, err := os.MkdirTemp(run.options.statePath(), ".repair-validate-")
	if err != nil {
		return err
	}
	defer func() { _ = removeTreeNoFollow(workspace) }()
	packPath, pathPath := filepath.Join(workspace, "packs"), filepath.Join(workspace, "paths")
	paths, err := os.OpenFile(pathPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = paths.Close() }()
	pathWriter := bufio.NewWriterSize(paths, 256<<10)
	if err := atomicWritePrivateGenerated(packPath, func(output io.Writer) error {
		return run.walkDataParts(txn, func(_ uint64, part stagedDataPart) error {
			if metadataPaths[part.RelativePath] {
				return fmt.Errorf("durable transaction contains a duplicate staged path")
			}
			if _, err := fmt.Fprintln(pathWriter, part.RelativePath); err != nil {
				return err
			}
			row, err := format.MarshalPackEntry(part.Entry)
			if err != nil {
				return err
			}
			_, err = output.Write(row)
			return err
		})
	}); err != nil {
		return err
	}
	if err := pathWriter.Flush(); err != nil {
		return err
	}
	if err := paths.Close(); err != nil {
		return err
	}
	if err := extsort.SortFiles(workspace, []string{pathPath}, filepath.Join(workspace, "paths-sorted"), extsort.Options{Unique: true, MaxLineBytes: maximumDataPartRecordBytes}); err != nil {
		return fmt.Errorf("validate unique staged data paths: %w", err)
	}
	sortedPacks := filepath.Join(workspace, "packs-sorted")
	if err := extsort.SortFiles(workspace, []string{packPath}, sortedPacks, extsort.Options{Unique: true, Key: packRecordKey}); err != nil {
		return fmt.Errorf("validate unique staged data parts: %w", err)
	}
	file, err := os.Open(sortedPacks)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 16<<10), 16<<10)
	next := scanner.Scan()
	if err := walkCatalog(func(entry format.PackEntry) error {
		row, err := format.MarshalPackEntry(entry)
		if err != nil {
			return err
		}
		if next && bytes.Equal(scanner.Bytes(), bytes.TrimSuffix(row, []byte{'\n'})) {
			next = scanner.Scan()
			return nil
		}
		if exact {
			return fmt.Errorf("staged data parts do not exactly match the changed candidate pack rows")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if next {
		return fmt.Errorf("staged data part does not match the candidate packs catalog")
	}
	return nil
}
