package repository

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/securefs"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

// BlobFile names one private, regular file containing an exact metadata blob.
// Size and BLAKE2b are checked every time the blob is opened so a durable
// candidate cannot silently change beneath validation or publication.
type BlobFile struct {
	Path    string
	Size    uint64
	BLAKE2b string
}

type stateSource interface {
	withBlob(name string, visit func(io.Reader) error) error
}

type memoryStateSource map[string][]byte

func (source memoryStateSource) withBlob(name string, visit func(io.Reader) error) error {
	data, ok := source[name]
	if !ok {
		return fmt.Errorf("metadata source lacks blob %q", name)
	}
	return visit(bytes.NewReader(data))
}

type fileStateSource map[string]BlobFile

func (source fileStateSource) withBlob(name string, visit func(io.Reader) error) error {
	blob, ok := source[name]
	if !ok {
		return fmt.Errorf("metadata source lacks blob %q", name)
	}
	if blob.Size > uint64(^uint64(0)>>1) {
		return fmt.Errorf("metadata blob %q size is not representable", name)
	}
	fd, err := unix.Open(blob.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open metadata blob %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), blob.Path)
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || uint64(stat.Size) != blob.Size {
		return fmt.Errorf("metadata blob %q has unexpected type or size", name)
	}
	hash, err := blake2b.New512(nil)
	if err != nil {
		return err
	}
	tracked := &countingReader{reader: io.TeeReader(io.LimitReader(file, int64(blob.Size)+1), hash)}
	visitErr := visit(tracked)
	if visitErr == nil {
		_, visitErr = io.Copy(io.Discard, tracked)
	}
	if visitErr != nil {
		return visitErr
	}
	if tracked.count != blob.Size || hex.EncodeToString(hash.Sum(nil)) != blob.BLAKE2b {
		return fmt.Errorf("metadata blob %q identity changed", name)
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	count  uint64
}

func (reader *countingReader) Read(data []byte) (int, error) {
	n, err := reader.reader.Read(data)
	if n > 0 {
		if ^uint64(0)-reader.count < uint64(n) {
			return 0, fmt.Errorf("metadata byte count overflow")
		}
		reader.count += uint64(n)
	}
	return n, err
}

// ParseFileState validates a complete file-backed metadata state without
// retaining any catalog rows or catalog bytes in memory.
func ParseFileState(files map[string]BlobFile, limits format.Limits) (State, error) {
	if len(files) != len(RequiredBlobNames) {
		return State{}, fmt.Errorf("metadata tree contains %d blobs, expected exactly %d", len(files), len(RequiredBlobNames))
	}
	source := make(fileStateSource, len(files))
	for _, name := range RequiredBlobNames {
		blob, ok := files[name]
		if !ok {
			return State{}, fmt.Errorf("metadata tree is missing required blob %q", name)
		}
		if blob.Path == "" || blob.BLAKE2b == "" {
			return State{}, fmt.Errorf("metadata blob %q has an incomplete file reference", name)
		}
		source[name] = blob
	}
	return parseStreamState(source, limits)
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	bounded := reader
	if maximum < int64(^uint64(0)>>1) {
		bounded = io.LimitReader(reader, maximum+1)
	}
	data, err := io.ReadAll(bounded)
	if err == nil && int64(len(data)) > maximum {
		err = fmt.Errorf("metadata exceeds %d bytes", maximum)
	}
	return data, err
}

func parseStreamState(source stateSource, limits format.Limits) (State, error) {
	state := State{source: source, BlobHashes: make(map[string]string, len(RequiredBlobNames)), BlobSizes: make(map[string]uint64, len(RequiredBlobNames))}
	readConfig := func(name string, maximum int64) ([]byte, error) {
		var data []byte
		err := source.withBlob(name, func(reader io.Reader) error {
			var err error
			data, err = readBounded(reader, maximum)
			if err != nil {
				return err
			}
			if int64(len(data)) > maximum {
				return fmt.Errorf("blob %q exceeds %d bytes", name, maximum)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		digest := blake2b.Sum512(data)
		state.BlobHashes[name] = hex.EncodeToString(digest[:])
		state.BlobSizes[name] = uint64(len(data))
		return data, nil
	}
	formatBytes, err := readConfig("FORMAT", minInt64(limits.MaxFileBytes, 64<<10))
	if err != nil {
		return State{}, err
	}
	state.Format, err = format.ParseRepositoryFormat(bytes.NewReader(formatBytes), limits)
	if err != nil {
		return State{}, err
	}
	ignoreBytes, err := readConfig("ignore", minInt64(limits.MaxFileBytes, format.MaximumIgnoreBytes))
	if err != nil {
		return State{}, err
	}
	state.Ignore, err = format.ParseIgnore(bytes.NewReader(ignoreBytes), limits)
	if err != nil {
		return State{}, err
	}
	keyBytes, err := readConfig(".publickeys", minInt64(limits.MaxFileBytes, format.MaximumPublicKeysBytes))
	if err != nil {
		return State{}, err
	}
	state.PublicKeys, err = format.ParsePublicKeys(bytes.NewReader(keyBytes), limits)
	if err != nil {
		return State{}, err
	}
	mirrorBytes, err := readConfig("mirrors.tsv", minInt64(limits.MaxFileBytes, format.MaximumMirrorsBytes))
	if err != nil {
		return State{}, err
	}
	state.Mirrors, err = format.ParseMirrors(bytes.NewReader(mirrorBytes), limits)
	if err != nil {
		return State{}, err
	}
	workspace, err := os.MkdirTemp("", "backup-catalog-validation-")
	if err != nil {
		return State{}, err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = securefs.RemoveTree(workspace)
		return State{}, err
	}
	defer func() { _ = securefs.RemoveTree(workspace) }()
	if err := validateStreamCatalogs(&state, limits, workspace); err != nil {
		return State{}, fmt.Errorf("metadata catalogs: %w", err)
	}
	if err := format.RequireRecoveryRecipient(state.PublicKeys, state.Format.RecoveryRecipientFingerprint); err != nil {
		return State{}, err
	}
	return state, nil
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (state State) withBlob(name string, visit func(io.Reader) error) error {
	if state.source == nil {
		return fmt.Errorf("metadata state lacks a blob source")
	}
	return state.source.withBlob(name, visit)
}

// WriteBlobFile atomically streams one validated blob to path.
func (state State) WriteBlobFile(name, path string, mode os.FileMode) error {
	return state.withBlob(name, func(reader io.Reader) error {
		return atomicWriteReader(path, reader, mode)
	})
}

// ReadBlob reads a size-bounded metadata blob. Catalog callers should use the
// Walk methods instead.
func (state State) ReadBlob(name string, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("invalid metadata read limit")
	}
	var data []byte
	err := state.withBlob(name, func(reader io.Reader) error {
		var err error
		data, err = readBounded(reader, maximum)
		return err
	})
	return data, err
}

func (state State) WalkIndex(limits format.Limits, visit func(format.IndexEntry) error) error {
	return state.withBlob("index.tsv", func(reader io.Reader) error { return format.WalkIndex(reader, limits, visit) })
}

func (state State) WalkObjects(limits format.Limits, visit func(format.ObjectEntry) error) error {
	return state.withBlob("objects.tsv", func(reader io.Reader) error { return format.WalkObjects(reader, limits, visit) })
}

func (state State) WalkPacks(limits format.Limits, visit func(format.PackEntry) error) error {
	return state.withBlob("packs.tsv", func(reader io.Reader) error { return format.WalkPacks(reader, limits, visit) })
}

func (state State) blobEqual(other State, name string) bool {
	leftHash, leftOK := state.BlobHashes[name]
	rightHash, rightOK := other.BlobHashes[name]
	return leftOK && rightOK && state.BlobSizes[name] == other.BlobSizes[name] && leftHash == rightHash
}

// Equal reports exact equality of all seven canonical metadata blobs.
func (state State) Equal(other State) bool {
	return statesEqual(state, other)
}

func validateStreamCatalogs(state *State, limits format.Limits, workspace string) error {
	indexReferences := filepath.Join(workspace, "index-references")
	ancestorEvents := filepath.Join(workspace, "ancestor-events")
	objectsByHash := filepath.Join(workspace, "objects-by-hash")
	objectsByPack := filepath.Join(workspace, "objects-by-pack")
	packHashes := filepath.Join(workspace, "pack-hashes")
	files, err := createPrivateFiles(indexReferences, ancestorEvents, objectsByHash, objectsByPack, packHashes)
	if err != nil {
		return err
	}
	indexRefs, events, objects, objectPacks, packs := files[0], files[1], files[2], files[3], files[4]
	closeAll := func() error {
		var result error
		for _, file := range files {
			if file != nil {
				result = errors.Join(result, file.Close())
			}
		}
		return result
	}
	failed := true
	defer func() {
		if failed {
			_ = closeAll()
		}
	}()

	indexHash, _ := blake2b.New512(nil)
	var indexBytes uint64
	err = state.withBlob("index.tsv", func(reader io.Reader) error {
		tracked := &countingReader{reader: io.TeeReader(reader, indexHash)}
		err := format.WalkIndex(tracked, limits, func(entry format.IndexEntry) error {
			state.IndexCount++
			if entry.Kind == format.KindFile {
				hash := strings.TrimPrefix(entry.Ref, "blake2b:")
				if _, err := fmt.Fprintf(indexRefs, "%s\t%d\t%s\n", hash, entry.Size, entry.Path); err != nil {
					return err
				}
			}
			encoded := hex.EncodeToString([]byte(entry.Path))
			start := hex.EncodeToString([]byte(entry.Path + "/"))
			end := hex.EncodeToString([]byte(entry.Path + "0"))
			if _, err := fmt.Fprintf(events, "%s\t2\n%s\t1\n%s\t0\n", encoded, start, end); err != nil {
				return err
			}
			return nil
		})
		indexBytes = tracked.count
		return err
	})
	if err != nil {
		return err
	}
	state.BlobHashes["index.tsv"] = hex.EncodeToString(indexHash.Sum(nil))
	state.BlobSizes["index.tsv"] = indexBytes

	objectsHash, _ := blake2b.New512(nil)
	var objectBytes uint64
	err = state.withBlob("objects.tsv", func(reader io.Reader) error {
		tracked := &countingReader{reader: io.TeeReader(reader, objectsHash)}
		err := format.WalkObjects(tracked, limits, func(entry format.ObjectEntry) error {
			state.ObjectCount++
			row, marshalErr := format.MarshalObjectEntry(entry)
			if marshalErr != nil {
				return marshalErr
			}
			if _, err := objects.Write(row); err != nil {
				return err
			}
			_, err := fmt.Fprintf(objectPacks, "%s\t%s\n", entry.PackHash, entry.PlaintextHash)
			return err
		})
		objectBytes = tracked.count
		return err
	})
	if err != nil {
		return err
	}
	state.BlobHashes["objects.tsv"] = hex.EncodeToString(objectsHash.Sum(nil))
	state.BlobSizes["objects.tsv"] = objectBytes

	packsHash, _ := blake2b.New512(nil)
	var packBytes uint64
	var previousPack string
	err = state.withBlob("packs.tsv", func(reader io.Reader) error {
		tracked := &countingReader{reader: io.TeeReader(reader, packsHash)}
		err := format.WalkPacks(tracked, limits, func(entry format.PackEntry) error {
			state.PackCount++
			if entry.PackHash != previousPack {
				if _, err := fmt.Fprintln(packs, entry.PackHash); err != nil {
					return err
				}
				previousPack = entry.PackHash
			}
			return nil
		})
		packBytes = tracked.count
		return err
	})
	if err != nil {
		return err
	}
	state.BlobHashes["packs.tsv"] = hex.EncodeToString(packsHash.Sum(nil))
	state.BlobSizes["packs.tsv"] = packBytes
	if err := closeAll(); err != nil {
		return err
	}
	failed = false

	keyFirstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("derived record lacks key")
		}
		return field, nil
	}
	sortedIndex := filepath.Join(workspace, "index-references-sorted")
	if err := extsort.SortFiles(workspace, []string{indexReferences}, sortedIndex, extsort.Options{Key: keyFirstField, MaxLineBytes: limits.MaxLineBytes}); err != nil {
		return err
	}
	sortedEvents := filepath.Join(workspace, "ancestor-events-sorted")
	if err := extsort.SortFiles(workspace, []string{ancestorEvents}, sortedEvents, extsort.Options{Key: keyFirstField, MaxLineBytes: 2*limits.MaxFieldBytes + 32}); err != nil {
		return err
	}
	sortedObjectPacks := filepath.Join(workspace, "objects-by-pack-sorted")
	if err := extsort.SortFiles(workspace, []string{objectsByPack}, sortedObjectPacks, extsort.Options{Key: keyFirstField, MaxLineBytes: limits.MaxLineBytes}); err != nil {
		return err
	}
	if err := validateAncestorEvents(sortedEvents, 2*limits.MaxFieldBytes+32); err != nil {
		return err
	}
	if err := mergeIndexObjects(sortedIndex, objectsByHash, limits.MaxLineBytes); err != nil {
		return err
	}
	if err := mergeObjectPacks(sortedObjectPacks, packHashes, limits.MaxLineBytes); err != nil {
		return err
	}
	return nil
}

func createPrivateFiles(paths ...string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func validateAncestorEvents(path string, maximumLine int) error {
	active := int64(0)
	return scanDerived(path, maximumLine, func(fields []string) error {
		if len(fields) != 2 {
			return fmt.Errorf("invalid ancestor event")
		}
		switch fields[1] {
		case "0":
			if active == 0 {
				return fmt.Errorf("invalid ancestor interval ordering")
			}
			active--
		case "1":
			if active == int64(^uint64(0)>>1) {
				return fmt.Errorf("ancestor interval count overflow")
			}
			active++
		case "2":
			if active != 0 {
				pathBytes, err := hex.DecodeString(fields[0])
				if err != nil {
					return fmt.Errorf("invalid encoded path event")
				}
				return fmt.Errorf("an indexed leaf is an ancestor of %q", string(pathBytes))
			}
		default:
			return fmt.Errorf("invalid ancestor event kind")
		}
		return nil
	}, func() error {
		if active != 0 {
			return fmt.Errorf("unterminated ancestor intervals")
		}
		return nil
	})
}

// scanDerived is kept deliberately small: all rows were generated from
// already validated canonical metadata and are still line-size bounded.
func scanDerived(path string, maximumLine int, visit func([]string) error, finish func() error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, min(maximumLine, 64<<10)), maximumLine+1)
	for scanner.Scan() {
		if err := visit(strings.Split(string(scanner.Bytes()), "\t")); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return finish()
}

func mergeIndexObjects(indexPath, objectsPath string, maximumLine int) error {
	index, err := newDerivedRows(indexPath, maximumLine)
	if err != nil {
		return err
	}
	defer func() { _ = index.Close() }()
	objects, err := newDerivedRows(objectsPath, maximumLine)
	if err != nil {
		return err
	}
	defer func() { _ = objects.Close() }()
	indexNext, objectNext := index.Next(), objects.Next()
	for indexNext {
		if len(index.Fields()) != 3 {
			return fmt.Errorf("invalid derived index reference")
		}
		for objectNext && objects.Fields()[0] < index.Fields()[0] {
			objectNext = objects.Next()
		}
		if !objectNext || len(objects.Fields()) != 3 || objects.Fields()[0] != index.Fields()[0] {
			return fmt.Errorf("file %q references missing object %s", index.Fields()[2], index.Fields()[0])
		}
		objectSize, parseErr := strconv.ParseUint(objects.Fields()[1], 10, 64)
		indexSize, indexErr := strconv.ParseUint(index.Fields()[1], 10, 64)
		if parseErr != nil || indexErr != nil || objectSize != indexSize {
			return fmt.Errorf("file %q size disagrees with object size", index.Fields()[2])
		}
		indexNext = index.Next()
	}
	return errors.Join(index.Err(), objects.Err())
}

func mergeObjectPacks(objectsPath, packsPath string, maximumLine int) error {
	objects, err := newDerivedRows(objectsPath, maximumLine)
	if err != nil {
		return err
	}
	defer func() { _ = objects.Close() }()
	packs, err := newDerivedRows(packsPath, maximumLine)
	if err != nil {
		return err
	}
	defer func() { _ = packs.Close() }()
	objectNext, packNext := objects.Next(), packs.Next()
	for objectNext {
		if len(objects.Fields()) != 2 {
			return fmt.Errorf("invalid derived object-pack reference")
		}
		for packNext && packs.Fields()[0] < objects.Fields()[0] {
			packNext = packs.Next()
		}
		if !packNext || len(packs.Fields()) != 1 || packs.Fields()[0] != objects.Fields()[0] {
			return fmt.Errorf("object %s references missing pack %s", objects.Fields()[1], objects.Fields()[0])
		}
		objectNext = objects.Next()
	}
	return errors.Join(objects.Err(), packs.Err())
}

type derivedRows struct {
	file    *os.File
	scanner *bufio.Scanner
	fields  []string
}

func newDerivedRows(path string, maximumLine int) (*derivedRows, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, min(maximumLine, 64<<10)), maximumLine+1)
	return &derivedRows{file: file, scanner: scanner}, nil
}

func (rows *derivedRows) Next() bool {
	if !rows.scanner.Scan() {
		rows.fields = nil
		return false
	}
	rows.fields = strings.Split(string(rows.scanner.Bytes()), "\t")
	return true
}

func (rows *derivedRows) Fields() []string { return rows.fields }
func (rows *derivedRows) Err() error       { return rows.scanner.Err() }
func (rows *derivedRows) Close() error     { return rows.file.Close() }
