package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/pack"
	"backup/internal/repository"
)

const captureSegmentVersion = 1

type captureSegment struct {
	Version      int           `json:"version"`
	Number       uint64        `json:"number"`
	StartPlan    int           `json:"start_plan"`
	EndPlan      int           `json:"end_plan"`
	PreviousHash string        `json:"previous_hash"`
	Index        stagedFileRef `json:"index"`
	Objects      stagedFileRef `json:"objects"`
	Packs        stagedFileRef `json:"packs"`
}

func stagedMetadataName(name string) string {
	switch name {
	case ".publickeys":
		return "publickeys"
	case "FORMAT":
		return "format"
	default:
		return name
	}
}

func (run *runtime) ensureStagedBytes(relative string, data []byte, current stagedFileRef) (stagedFileRef, error) {
	return run.ensureStagedBytesWithIdentity(relative, data, current, objectstore.HashBytes(data))
}

func (run *runtime) ensureContentAddressedStagedBytes(prefix, suffix string, data []byte, current stagedFileRef) (stagedFileRef, error) {
	identity := objectstore.HashBytes(data)
	return run.ensureStagedBytesWithIdentity(prefix+identity.BLAKE2b+suffix, data, current, identity)
}

func (run *runtime) ensureStagedBytesWithIdentity(relative string, data []byte, current stagedFileRef, identity objectstore.Object) (stagedFileRef, error) {
	if current.RelativePath == relative && current.BLAKE2b == identity.BLAKE2b && current.Size == identity.Size {
		return current, nil
	}
	path, err := run.stagedPath(relative)
	if err != nil {
		return stagedFileRef{}, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return stagedFileRef{}, err
	}
	if err := atomicWritePrivate(path, data); err != nil {
		return stagedFileRef{}, err
	}
	return stagedFileRef{RelativePath: relative, BLAKE2b: identity.BLAKE2b, Size: identity.Size}, nil
}

func (run *runtime) stageCandidateBlobs(txn *transaction, blobs map[string][]byte) error {
	if txn == nil || len(blobs) != len(repository.RequiredBlobNames) {
		return fmt.Errorf("candidate requires exactly seven metadata blobs")
	}
	if txn.CandidateFiles == nil {
		txn.CandidateFiles = make(map[string]stagedFileRef, len(repository.RequiredBlobNames))
	}
	if txn.CandidateHashes == nil {
		txn.CandidateHashes = make(map[string]string, len(repository.RequiredBlobNames))
	}
	for _, name := range repository.RequiredBlobNames {
		data, ok := blobs[name]
		if !ok {
			return fmt.Errorf("candidate lacks metadata blob %q", name)
		}
		current := txn.CandidateFiles[name]
		ref, err := run.ensureContentAddressedStagedBytes(filepath.Join("candidate", stagedMetadataName(name)+"-"), "", data, current)
		if err != nil {
			return err
		}
		txn.CandidateFiles[name] = ref
		txn.CandidateHashes[name] = ref.BLAKE2b
	}
	return nil
}

func (run *runtime) stageCandidateState(txn *transaction, state repository.State) error {
	if txn == nil || len(state.BlobHashes) != len(repository.RequiredBlobNames) || len(state.BlobSizes) != len(repository.RequiredBlobNames) {
		return fmt.Errorf("candidate requires a complete validated metadata state")
	}
	txn.CandidateFiles = make(map[string]stagedFileRef, len(repository.RequiredBlobNames))
	txn.CandidateHashes = make(map[string]string, len(repository.RequiredBlobNames))
	for _, name := range repository.RequiredBlobNames {
		relative := filepath.Join("candidate", stagedMetadataName(name)+"-"+state.BlobHashes[name])
		path, err := run.stagedPath(relative)
		if err != nil {
			return err
		}
		if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if err := state.WriteBlobFile(name, path, 0o600); err != nil {
			return err
		}
		ref := stagedFileRef{RelativePath: relative, BLAKE2b: state.BlobHashes[name], Size: state.BlobSizes[name]}
		txn.CandidateFiles[name] = ref
		txn.CandidateHashes[name] = ref.BLAKE2b
	}
	return nil
}

func (run *runtime) loadCandidateState(txn *transaction) (repository.State, error) {
	if txn == nil || len(txn.CandidateFiles) != len(repository.RequiredBlobNames) {
		return repository.State{}, fmt.Errorf("transaction has no complete file-backed candidate")
	}
	if run.candidateState != nil && equalHashes(txn.CandidateHashes, run.candidateState.BlobHashes) {
		return *run.candidateState, nil
	}
	files := make(map[string]repository.BlobFile, len(repository.RequiredBlobNames))
	for _, name := range repository.RequiredBlobNames {
		ref, ok := txn.CandidateFiles[name]
		if !ok {
			return repository.State{}, fmt.Errorf("candidate lacks metadata blob %q", name)
		}
		path, err := run.stagedPath(ref.RelativePath)
		if err != nil {
			return repository.State{}, err
		}
		files[name] = repository.BlobFile{Path: path, Size: ref.Size, BLAKE2b: ref.BLAKE2b}
	}
	state, err := repository.ParseFileState(files, format.DefaultLimits())
	if err != nil {
		return repository.State{}, err
	}
	run.candidateState = &state
	return state, nil
}

func (run *runtime) hydrateTransactionFiles(txn *transaction) error {
	if txn.Plan != nil {
		if err := run.validateStagedRef(txn.Plan.IndexFile); err != nil {
			return fmt.Errorf("validate staged add plan: %w", err)
		}
		for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
			ref, ok := txn.Plan.ConfigFiles[name]
			if !ok {
				return fmt.Errorf("staged add plan lacks configuration %q", name)
			}
			if err := run.validateStagedRef(ref); err != nil {
				return fmt.Errorf("validate staged configuration %q: %w", name, err)
			}
		}
	}
	if len(txn.CandidateFiles) != 0 {
		for _, name := range repository.RequiredBlobNames {
			ref, ok := txn.CandidateFiles[name]
			if !ok {
				return fmt.Errorf("staged candidate lacks blob %q", name)
			}
			if err := run.validateStagedRef(ref); err != nil {
				return fmt.Errorf("validate staged candidate %q: %w", name, err)
			}
		}
	}
	count, err := run.readDataParts(txn.DataPartsFile, nil)
	if err != nil {
		return fmt.Errorf("decode staged data parts: %w", err)
	}
	txn.DataPartCount = count
	if txn.Capture != nil {
		if err := run.validateCaptureSegments(txn); err != nil {
			return err
		}
	}
	return nil
}

func (run *runtime) readStagedRef(ref stagedFileRef, maximum int64) ([]byte, error) {
	if ref.RelativePath == "" || maximum < 0 || ref.Size > uint64(maximum) {
		return nil, fmt.Errorf("invalid staged file reference")
	}
	data, err := run.readStaged(ref.RelativePath, int64(ref.Size))
	if err != nil {
		return nil, err
	}
	identity := objectstore.HashBytes(data)
	if identity.Size != ref.Size || identity.BLAKE2b != ref.BLAKE2b {
		return nil, fmt.Errorf("staged file %q identity changed", ref.RelativePath)
	}
	return data, nil
}

func (run *runtime) validateStagedRef(ref stagedFileRef) error {
	if ref.RelativePath == "" || ref.Size > uint64(^uint64(0)>>1) {
		return fmt.Errorf("invalid staged file reference")
	}
	file, err := run.openStaged(ref.RelativePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	identity, err := objectstore.HashReader(file)
	if err != nil {
		return err
	}
	if identity.Size != ref.Size || identity.BLAKE2b != ref.BLAKE2b {
		return fmt.Errorf("staged file %q identity changed", ref.RelativePath)
	}
	return nil
}

func decodeOneJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func (run *runtime) readPlanConfig(txn *transaction, name string) ([]byte, error) {
	if txn == nil || txn.Plan == nil {
		return nil, fmt.Errorf("transaction has no add plan")
	}
	ref, ok := txn.Plan.ConfigFiles[name]
	if !ok || ref.Size > 256<<20 {
		return nil, fmt.Errorf("add plan lacks bounded configuration %q", name)
	}
	return run.readStagedRef(ref, int64(ref.Size))
}

func (run *runtime) walkPlan(txn *transaction, start int, visit func(int, format.IndexEntry) error) error {
	if txn == nil || txn.Plan == nil || start < 0 || start > txn.Plan.Entries || visit == nil {
		return fmt.Errorf("invalid add-plan walk")
	}
	file, err := run.openStaged(txn.Plan.IndexFile.RelativePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	position := 0
	if err := format.WalkIndex(file, format.DefaultLimits(), func(entry format.IndexEntry) error {
		current := position
		position++
		if current < start {
			return nil
		}
		return visit(current, entry)
	}); err != nil {
		return err
	}
	if position != txn.Plan.Entries {
		return fmt.Errorf("staged add-plan entry count changed")
	}
	return nil
}

func (run *runtime) writeCaptureSegment(txn *transaction, start, end int, index []format.IndexEntry, created *pack.Created) error {
	if txn == nil || txn.Plan == nil || txn.Capture == nil || start != txn.Capture.NextPlan || end < start || end > txn.Plan.Entries {
		return fmt.Errorf("invalid capture segment range")
	}
	indexBytes, err := format.MarshalIndex(index)
	if err != nil {
		return err
	}
	var objects []format.ObjectEntry
	if created != nil {
		objects = append(objects, created.Objects...)
		format.SortObjects(objects)
	}
	objectsBytes, err := format.MarshalObjects(objects)
	if err != nil {
		return err
	}
	number := txn.Capture.SegmentCount
	prefix := filepath.Join("progress", fmt.Sprintf("segment-%08d", number))
	indexRef, err := run.ensureStagedBytes(prefix+"-index.tsv", indexBytes, stagedFileRef{})
	if err != nil {
		return err
	}
	objectsRef, err := run.ensureStagedBytes(prefix+"-objects.tsv", objectsBytes, stagedFileRef{})
	if err != nil {
		return err
	}
	packsRelative := prefix + "-packs.tsv"
	packsPath, err := run.stagedPath(packsRelative)
	if err != nil {
		return err
	}
	if err := atomicWritePrivateGenerated(packsPath, func(writer io.Writer) error {
		if created == nil {
			return nil
		}
		return created.WalkParts(func(entry format.PackEntry) error {
			row, err := format.MarshalPackEntry(entry)
			if err != nil {
				return err
			}
			written, err := writer.Write(row)
			if err == nil && written != len(row) {
				err = io.ErrShortWrite
			}
			return err
		})
	}); err != nil {
		return err
	}
	packsRef, err := run.referenceStagedFile(packsRelative)
	if err != nil {
		return err
	}
	segment := captureSegment{
		Version: captureSegmentVersion, Number: number, StartPlan: start, EndPlan: end,
		PreviousHash: txn.Capture.SegmentHash, Index: indexRef, Objects: objectsRef, Packs: packsRef,
	}
	descriptor, err := json.Marshal(segment)
	if err != nil {
		return err
	}
	descriptor = append(descriptor, '\n')
	if _, err := run.ensureStagedBytes(prefix+".json", descriptor, stagedFileRef{}); err != nil {
		return err
	}
	if ^uint64(0)-txn.Capture.Entries < uint64(len(index)) {
		return fmt.Errorf("captured entry count overflow")
	}
	txn.Capture.Entries += uint64(len(index))
	txn.Capture.NextPlan = end
	txn.Capture.SegmentCount++
	txn.Capture.SegmentHash = objectstore.HashBytes(descriptor).BLAKE2b
	return run.saveTransaction(txn)
}

func (run *runtime) validateCaptureSegments(txn *transaction) error {
	capture := txn.Capture
	cursor := 0
	previousHash := ""
	var entries uint64
	for number := uint64(0); number < capture.SegmentCount; number++ {
		relative := filepath.Join("progress", fmt.Sprintf("segment-%08d.json", number))
		data, err := run.readStaged(relative, 64<<10)
		if err != nil {
			return err
		}
		if len(data) == 0 || data[len(data)-1] != '\n' || int64(len(data)) > 64<<10 {
			return fmt.Errorf("invalid capture segment descriptor %d", number)
		}
		var segment captureSegment
		if err := decodeOneJSON(data, &segment); err != nil {
			return fmt.Errorf("decode capture segment %d: %w", number, err)
		}
		if segment.Version != captureSegmentVersion || segment.Number != number || segment.StartPlan != cursor || segment.EndPlan < cursor || segment.EndPlan > txn.Plan.Entries || segment.PreviousHash != previousHash {
			return fmt.Errorf("invalid capture segment chain at %d", number)
		}
		for _, ref := range []stagedFileRef{segment.Index, segment.Objects, segment.Packs} {
			if err := run.validateStagedRef(ref); err != nil {
				return err
			}
		}
		indexFile, err := run.openStaged(segment.Index.RelativePath)
		if err != nil {
			return err
		}
		err = format.WalkIndex(indexFile, format.DefaultLimits(), func(format.IndexEntry) error {
			entries++
			return nil
		})
		closeErr := indexFile.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		objectsFile, err := run.openStaged(segment.Objects.RelativePath)
		if err != nil {
			return err
		}
		err = format.WalkObjects(objectsFile, format.DefaultLimits(), nil)
		closeErr = objectsFile.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		packsFile, err := run.openStaged(segment.Packs.RelativePath)
		if err != nil {
			return err
		}
		err = format.WalkPacks(packsFile, format.DefaultLimits(), nil)
		closeErr = packsFile.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		cursor = segment.EndPlan
		previousHash = objectstore.HashBytes(data).BLAKE2b
	}
	if cursor != capture.NextPlan || previousHash != capture.SegmentHash || entries != capture.Entries {
		return fmt.Errorf("capture segment chain does not match durable progress")
	}
	return nil
}
