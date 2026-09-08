package backup

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func (run *runtime) validateCapturedCandidate(txn *transaction, base, candidate repository.State) error {
	if run.capturedCandidateValidated {
		return nil
	}
	workspace, err := os.MkdirTemp(run.options.statePath(), ".candidate-validate-")
	if err != nil {
		return err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = removeTreeNoFollow(workspace)
		return err
	}
	defer func() { _ = removeTreeNoFollow(workspace) }()
	if err := run.writeCandidateFiles(txn, base, workspace, false); err != nil {
		return err
	}
	for _, name := range repository.RequiredBlobNames {
		path := filepath.Join(workspace, stagedMetadataName(name))
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		identity, hashErr := objectstore.HashReader(file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return errors.Join(hashErr, closeErr)
		}
		if identity.Size != candidate.BlobSizes[name] || identity.BLAKE2b != candidate.BlobHashes[name] {
			return fmt.Errorf("captured progress does not reproduce candidate blob %q", name)
		}
	}
	run.capturedCandidateValidated = true
	return nil
}

func (run *runtime) buildCandidateFiles(txn *transaction, base repository.State) error {
	candidateDirectory := filepath.Join(run.options.transactionFilesPath(), "candidate")
	if err := run.writeCandidateFiles(txn, base, candidateDirectory, true); err != nil {
		return err
	}
	run.capturedCandidateValidated = true
	return nil
}

func (run *runtime) writeCandidateFiles(txn *transaction, base repository.State, candidateDirectory string, record bool) error {
	if txn == nil || txn.Plan == nil || txn.Capture == nil || candidateDirectory == "" {
		return fmt.Errorf("candidate build requires a completed capture")
	}
	if err := ensurePrivateDirectory(candidateDirectory); err != nil {
		return err
	}
	indexInputs, objectInputs, packInputs, err := run.captureSegmentInputPaths(txn, true)
	if err != nil {
		return err
	}
	baseDirectory, err := os.MkdirTemp(filepath.Dir(candidateDirectory), ".candidate-base-")
	if err != nil {
		return err
	}
	if err := os.Chmod(baseDirectory, 0o700); err != nil {
		_ = removeTreeNoFollow(baseDirectory)
		return err
	}
	defer func() { _ = removeTreeNoFollow(baseDirectory) }()
	baseObjects := filepath.Join(baseDirectory, "objects.tsv")
	basePacks := filepath.Join(baseDirectory, "packs.tsv")
	if err := base.WriteBlobFile("objects.tsv", baseObjects, 0o600); err != nil {
		return err
	}
	if err := base.WriteBlobFile("packs.tsv", basePacks, 0o600); err != nil {
		return err
	}
	objectInputs = append([]string{baseObjects}, objectInputs...)
	packInputs = append([]string{basePacks}, packInputs...)
	firstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("record lacks its first TSV field")
		}
		return field, nil
	}
	packKey := func(record []byte) ([]byte, error) {
		fields := bytes.Split(record, []byte{'\t'})
		if len(fields) != 8 || len(fields[0]) != 128 {
			return nil, fmt.Errorf("invalid pack row")
		}
		part, err := strconv.ParseUint(string(fields[1]), 10, 32)
		if err != nil || strconv.FormatUint(part, 10) != string(fields[1]) {
			return nil, fmt.Errorf("invalid canonical pack part number")
		}
		key := make([]byte, 132)
		copy(key, fields[0])
		binary.BigEndian.PutUint32(key[128:], uint32(part))
		return key, nil
	}
	workspace := run.options.transactionFilesPath()
	if err := extsort.SortFiles(workspace, indexInputs, filepath.Join(candidateDirectory, "index.tsv"), extsort.Options{Unique: true, Key: firstField}); err != nil {
		return fmt.Errorf("sort captured index: %w", err)
	}
	if err := extsort.SortFiles(workspace, objectInputs, filepath.Join(candidateDirectory, "objects.tsv"), extsort.Options{Unique: true, Key: firstField}); err != nil {
		return fmt.Errorf("merge object catalog: %w", err)
	}
	if err := extsort.SortFiles(workspace, packInputs, filepath.Join(candidateDirectory, "packs.tsv"), extsort.Options{Unique: true, Key: packKey}); err != nil {
		return fmt.Errorf("merge pack catalog: %w", err)
	}
	for _, name := range []string{"FORMAT", "ignore", ".publickeys", "mirrors.tsv"} {
		var data []byte
		if name == "FORMAT" {
			data, err = base.ReadBlob(name, 64<<10)
		} else {
			data, err = run.readPlanConfig(txn, name)
		}
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("candidate source lacks metadata %q", name)
		}
		path := filepath.Join(candidateDirectory, stagedMetadataName(name))
		if err := atomicWritePrivate(path, data); err != nil {
			return err
		}
	}

	if !record {
		return nil
	}
	txn.CandidateFiles = make(map[string]stagedFileRef, 7)
	txn.CandidateHashes = make(map[string]string, 7)
	for _, name := range repository.RequiredBlobNames {
		relative := filepath.Join("candidate", stagedMetadataName(name))
		ref, err := run.referenceStagedFile(relative)
		if err != nil {
			return err
		}
		txn.CandidateFiles[name] = ref
		txn.CandidateHashes[name] = ref.BLAKE2b
	}
	return nil
}

func (run *runtime) rewriteCandidatePackObjectID(txn *transaction, target format.PackEntry, newID string) error {
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		return err
	}
	directory := filepath.Join(run.options.transactionFilesPath(), "candidate")
	temporary, err := os.CreateTemp(directory, ".packs-rewrite-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	writer := bufio.NewWriterSize(temporary, 256<<10)
	found := false
	if err := candidate.WalkPacks(format.DefaultLimits(), func(entry format.PackEntry) error {
		if entry.PackHash == target.PackHash && entry.PartNumber == target.PartNumber && entry.ObjectID == target.ObjectID {
			if found {
				return fmt.Errorf("candidate packs catalog contains a duplicate target part")
			}
			entry.ObjectID = newID
			found = true
		}
		row, err := format.MarshalPackEntry(entry)
		if err != nil {
			return err
		}
		_, err = writer.Write(row)
		return err
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("staged data part is absent from candidate packs catalog")
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	input, err := os.Open(temporaryPath)
	if err != nil {
		return err
	}
	identity, hashErr := objectstore.HashReader(input)
	closeErr := input.Close()
	if hashErr != nil || closeErr != nil {
		return errors.Join(hashErr, closeErr)
	}
	relative := filepath.Join("candidate", "packs.tsv-"+identity.BLAKE2b)
	destination, err := run.stagedPath(relative)
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	published = true
	if err := syncDirectory(directory); err != nil {
		return err
	}
	ref := stagedFileRef{RelativePath: relative, BLAKE2b: identity.BLAKE2b, Size: identity.Size}
	txn.CandidateFiles["packs.tsv"] = ref
	txn.CandidateHashes["packs.tsv"] = ref.BLAKE2b
	return nil
}

func (run *runtime) referenceStagedFile(relative string) (stagedFileRef, error) {
	file, err := run.openStaged(relative)
	if err != nil {
		return stagedFileRef{}, err
	}
	defer file.Close()
	identity, err := objectstore.HashReader(file)
	if err != nil {
		return stagedFileRef{}, err
	}
	return stagedFileRef{RelativePath: relative, BLAKE2b: identity.BLAKE2b, Size: identity.Size}, nil
}

func (run *runtime) captureSegmentInputPaths(txn *transaction, requireComplete bool) ([]string, []string, []string, error) {
	var indexes, objects, packs []string
	cursor := 0
	previousHash := ""
	for number := uint64(0); number < txn.Capture.SegmentCount; number++ {
		relative := filepath.Join("progress", fmt.Sprintf("segment-%08d.json", number))
		data, err := run.readStaged(relative, 64<<10)
		if err != nil {
			return nil, nil, nil, err
		}
		var segment captureSegment
		if err := decodeOneJSON(data, &segment); err != nil {
			return nil, nil, nil, err
		}
		if segment.Version != captureSegmentVersion || segment.Number != number || segment.StartPlan != cursor || segment.EndPlan < cursor || segment.EndPlan > txn.Plan.Entries || segment.PreviousHash != previousHash {
			return nil, nil, nil, fmt.Errorf("invalid capture segment chain at %d", number)
		}
		for _, ref := range []stagedFileRef{segment.Index, segment.Objects, segment.Packs} {
			if err := run.validateStagedRef(ref); err != nil {
				return nil, nil, nil, err
			}
		}
		indexPath, _ := run.stagedPath(segment.Index.RelativePath)
		objectPath, _ := run.stagedPath(segment.Objects.RelativePath)
		packPath, _ := run.stagedPath(segment.Packs.RelativePath)
		indexes = append(indexes, indexPath)
		objects = append(objects, objectPath)
		packs = append(packs, packPath)
		cursor = segment.EndPlan
		previousHash = objectstore.HashBytes(data).BLAKE2b
	}
	if cursor != txn.Capture.NextPlan || previousHash != txn.Capture.SegmentHash || requireComplete && cursor != txn.Plan.Entries {
		return nil, nil, nil, fmt.Errorf("capture segments do not match the add-plan cursor")
	}
	return indexes, objects, packs, nil
}

func (run *runtime) walkCapturedPacks(txn *transaction, visit func(format.PackEntry) error) error {
	_, _, paths, err := run.captureSegmentInputPaths(txn, true)
	if err != nil {
		return err
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		walkErr := format.WalkPacks(file, format.DefaultLimits(), visit)
		closeErr := file.Close()
		if walkErr != nil {
			return walkErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
