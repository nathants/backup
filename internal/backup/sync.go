package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/localconfig"
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
	txn, err := run.loadTransaction()
	if err != nil {
		return result, err
	}
	head, history, err := run.validatedHead(txn == nil || !txn.LocalAccepted)
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
	source, err := run.client(ctx, sourcePin)
	if err != nil {
		return result, err
	}
	destination, err := run.client(ctx, destinationPin)
	if err != nil {
		return result, err
	}
	if err := run.auditMirror(ctx, sourcePin, history, selected, txn); err != nil {
		return result, fmt.Errorf("source data catalog: %w", err)
	}
	// Observe destination loss before attempting immutable catch-up. Absence
	// on an unacknowledged/lagging mirror is not an integrity incident.
	if err := run.observeSyncDestination(ctx, destinationPin, history, selected, txn); err != nil {
		return result, err
	}
	copying := mirrorCopy{run: run, source: source, destination: destination, sourceName: sourceName, destinationName: destinationName}
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
		copied, copyErr := copying.copyObject(ctx, key, expected, path)
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
			copied, copyErr := copying.copyObject(ctx, key, expected, path)
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
		copied, copyErr := copying.ensureObject(ctx, manifestKey, manifestExpected, manifestPath)
		removeErr := os.Remove(manifestPath)
		if copyErr != nil || removeErr != nil {
			return errors.Join(copyErr, removeErr)
		}
		if copied {
			result.MetadataCopied++
		}
		return nil
	}
	if err := auditManifestChain(ctx, source, history, targetIndex, selected.State.Format.RepositoryUUID, txn, copyMetadata); err != nil {
		return result, fmt.Errorf("source metadata chain: %w", err)
	}
	before, err := run.loadLedger(selected.State.Format.RepositoryUUID)
	if err != nil {
		return result, err
	}
	for _, pin := range []localconfig.Mirror{sourcePin, destinationPin} {
		if err := run.auditMirror(ctx, pin, history, selected, txn); err != nil {
			return result, err
		}
	}
	ledger, err := run.loadLedger(selected.State.Format.RepositoryUUID)
	if err != nil {
		return result, err
	}
	if ledger.Incident != before.Incident {
		return result, fmt.Errorf("new integrity incident during sync; verify mirrors before resuming backups")
	}
	for _, name := range []string{sourceName, destinationName} {
		if selected.CommitID == head.CommitID {
			delete(ledger.Quarantined, name)
		}
		if !ledger.Quarantined[name] {
			if err := updateCompletionLedgerForSync(&ledger, name, selected.CommitID, history); err != nil {
				return result, err
			}
		}
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
		return fmt.Errorf("completion ledger for mirror %s names a commit outside validated history; rebuild it with verification", mirror)
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

type mirrorCopy struct {
	run                         *runtime
	source, destination         *objectstore.Client
	sourceName, destinationName string
}

func (copying mirrorCopy) auditDestination(ctx context.Context, key string, expected objectstore.Object) error {
	err := copying.destination.Audit(ctx, key, expected)
	if observationErr := copying.run.observeDataFailure(copying.destinationName, key, err); observationErr != nil {
		return observationErr
	}
	return err
}

func (copying mirrorCopy) copyObject(ctx context.Context, key string, expected objectstore.Object, path string) (bool, error) {
	if err := copying.auditDestination(ctx, key, expected); err == nil {
		return false, nil
	} else if isIncidentStateError(err) {
		return false, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	if err := copying.source.GetVerified(ctx, key, expected, file); err != nil {
		_ = file.Close()
		if observationErr := copying.run.observeDataFailure(copying.sourceName, key, err); observationErr != nil {
			return false, observationErr
		}
		return false, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	return copying.ensureObject(ctx, key, expected, path)
}

func (copying mirrorCopy) ensureObject(ctx context.Context, key string, expected objectstore.Object, path string) (bool, error) {
	if err := copying.auditDestination(ctx, key, expected); err == nil {
		return false, nil
	} else if isIncidentStateError(err) {
		return false, err
	}
	result := copying.destination.PutFile(ctx, key, path, expected)
	if result.Disposition == objectstore.CreateAcknowledged {
		return true, nil
	}
	if result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous {
		if err := copying.auditDestination(ctx, key, expected); err == nil {
			return false, nil
		} else if isIncidentStateError(err) {
			return false, err
		}
	}
	return false, fmt.Errorf("destination did not accept immutable object %s: %s", key, errorText(result.Err))
}
