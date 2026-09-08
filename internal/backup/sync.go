package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/objectstore"
)

func Sync(ctx context.Context, options Options, sourceName, destinationName, revision string) (SyncResult, error) {
	result := SyncResult{Source: sourceName, Destination: destinationName}
	if sourceName == "" || destinationName == "" || sourceName == destinationName {
		return result, fmt.Errorf("distinct source and destination mirror names are required")
	}
	run, err := openRuntime(options, true)
	if err != nil {
		return result, err
	}
	defer func() { _ = run.close() }()
	if txn, err := run.loadTransaction(); err != nil {
		return result, err
	} else if txn != nil {
		return result, fmt.Errorf("finish or reset the staged transaction before mirror sync")
	}
	head, history, err := run.validatedHead(true)
	if err != nil {
		return result, err
	}
	defer func() { _ = history.Close() }()
	if err := run.requirePinnedMirrors(head.State); err != nil {
		return result, err
	}
	selected, err := resolveHistoryRevision(run.repo, history, revision)
	if err != nil {
		return result, err
	}
	result.CommitID = selected.CommitID
	targetIndex, found, err := history.IndexOf(selected.CommitID)
	if err != nil {
		return result, err
	}
	if !found {
		return result, fmt.Errorf("selected metadata revision is outside validated history")
	}
	sourcePin, ok := run.mirror(sourceName)
	if !ok {
		return result, fmt.Errorf("unknown source mirror %q", sourceName)
	}
	destinationPin, ok := run.mirror(destinationName)
	if !ok {
		return result, fmt.Errorf("unknown destination mirror %q", destinationName)
	}
	source, err := run.reader(ctx, sourcePin)
	if err != nil {
		return result, err
	}
	destinationReader, err := run.reader(ctx, destinationPin)
	if err != nil {
		return result, err
	}
	destinationWriter, err := run.writer(ctx, destinationPin)
	if err != nil {
		return result, err
	}
	if err := auditDataCatalog(ctx, source, selected.State); err != nil {
		return result, fmt.Errorf("source data catalog: %w", err)
	}
	stage, err := os.MkdirTemp(run.options.statePath(), ".backup-sync-*")
	if err != nil {
		return result, err
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		return result, err
	}
	defer func() { _ = removeTreeNoFollow(stage) }()
	var dataIndex uint64
	if err := selected.State.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		key, _ := format.ObjectKey(part.PartHash, part.ObjectID)
		expected := objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5}
		if err := requireWorkspaceCapacity(stage, part.PartSize, 1, run.options.SpaceReserveBytes); err != nil {
			return fmt.Errorf("stage sync object %s: %w", key, err)
		}
		path := filepath.Join(stage, fmt.Sprintf("data-%08d", dataIndex))
		copied, copyErr := copyMirrorObject(ctx, source, destinationReader, destinationWriter, key, expected, path)
		removeErr := os.Remove(path)
		if os.IsNotExist(removeErr) {
			removeErr = nil
		}
		if copyErr != nil || removeErr != nil {
			return errors.Join(copyErr, removeErr)
		}
		dataIndex++
		if copied {
			result.DataCopied++
		}
		return nil
	}); err != nil {
		return result, err
	}
	copyMetadata := func(edgeIndex int, representation manifestRepresentation) error {
		for partIndex, part := range representation.Manifest.Parts {
			key, _ := format.MetadataPartKey(part)
			expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
			if err := requireWorkspaceCapacity(stage, part.Size, 1, run.options.SpaceReserveBytes); err != nil {
				return fmt.Errorf("stage metadata sync object %s: %w", key, err)
			}
			path := filepath.Join(stage, fmt.Sprintf("metadata-%08d-%08d", edgeIndex, partIndex))
			copied, copyErr := copyMirrorObject(ctx, source, destinationReader, destinationWriter, key, expected, path)
			removeErr := os.Remove(path)
			if os.IsNotExist(removeErr) {
				removeErr = nil
			}
			if copyErr != nil || removeErr != nil {
				return errors.Join(copyErr, removeErr)
			}
			if copied {
				result.MetadataCopied++
			}
		}
		manifestKey, _ := format.MetadataManifestKey(representation.Manifest.TipCommit, representation.Hash, representation.ObjectID)
		manifestExpected := objectstore.HashBytes(representation.Data)
		if err := requireWorkspaceCapacity(stage, uint64(len(representation.Data)), 1, run.options.SpaceReserveBytes); err != nil {
			return fmt.Errorf("stage metadata manifest %s: %w", manifestKey, err)
		}
		manifestPath := filepath.Join(stage, fmt.Sprintf("manifest-%08d", edgeIndex))
		if err := os.WriteFile(manifestPath, representation.Data, 0o600); err != nil {
			return err
		}
		copied, copyErr := ensureDestinationObject(ctx, destinationReader, destinationWriter, manifestKey, manifestExpected, manifestPath)
		removeErr := os.Remove(manifestPath)
		if copyErr != nil || removeErr != nil {
			return errors.Join(copyErr, removeErr)
		}
		if copied {
			result.MetadataCopied++
		}
		return nil
	}
	if err := auditManifestChain(ctx, source, history, targetIndex, selected.State.Format.RepositoryUUID, copyMetadata); err != nil {
		return result, fmt.Errorf("source metadata chain: %w", err)
	}
	if err := auditManifestChain(ctx, destinationReader, history, targetIndex, selected.State.Format.RepositoryUUID, nil); err != nil {
		return result, fmt.Errorf("destination metadata verification: %w", err)
	}
	if err := auditDataCatalog(ctx, destinationReader, selected.State); err != nil {
		return result, fmt.Errorf("destination data verification: %w", err)
	}
	ledger, err := run.loadLedger(selected.State.Format.RepositoryUUID)
	if err != nil {
		return result, err
	}
	if err := updateCompletionLedgerForSync(&ledger, destinationName, selected.CommitID, history); err != nil {
		return result, err
	}
	if err := run.saveLedger(ledger); err != nil {
		return result, err
	}
	return result, nil
}

type indexedHistory interface {
	IndexOf(commitID string) (int, bool, error)
}

func updateCompletionLedgerForSync(ledger *completionLedger, mirror, selected string, history indexedHistory) error {
	if ledger == nil || mirror == "" || !isCommitID(selected) || history == nil {
		return fmt.Errorf("invalid completion-ledger sync update")
	}
	current := ledger.Mirrors[mirror]
	if current == "" || current == selected {
		ledger.Mirrors[mirror] = selected
		return nil
	}
	currentIndex, currentFound, err := history.IndexOf(current)
	if err != nil {
		return err
	}
	selectedIndex, selectedFound, err := history.IndexOf(selected)
	if err != nil {
		return err
	}
	if !currentFound {
		return fmt.Errorf("completion ledger for mirror %s names a commit outside validated history; rebuild it with reader/auditor verification", mirror)
	}
	if !selectedFound {
		return fmt.Errorf("selected revision is outside validated history")
	}
	if selectedIndex < currentIndex {
		return fmt.Errorf("refusing to regress mirror %s completion ledger from %s to ancestor %s", mirror, current, selected)
	}
	ledger.Mirrors[mirror] = selected
	return nil
}

func copyMirrorObject(ctx context.Context, source, destinationReader, destinationWriter *objectstore.Client, key string, expected objectstore.Object, path string) (bool, error) {
	if err := destinationReader.Audit(ctx, key, expected); err == nil {
		return false, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	if err := source.GetVerified(ctx, key, expected, file); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	return ensureDestinationObject(ctx, destinationReader, destinationWriter, key, expected, path)
}

func ensureDestinationObject(ctx context.Context, reader, writer *objectstore.Client, key string, expected objectstore.Object, path string) (bool, error) {
	if err := reader.Audit(ctx, key, expected); err == nil {
		return false, nil
	}
	result := writer.PutFile(ctx, key, path, expected)
	if result.Disposition == objectstore.CreateAcknowledged {
		return true, nil
	}
	if (result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous) && reader.Audit(ctx, key, expected) == nil {
		return false, nil
	}
	return false, fmt.Errorf("destination did not accept immutable object %s: %s", key, errorText(result.Err))
}
