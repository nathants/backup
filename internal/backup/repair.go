package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func RepairDataPart(ctx context.Context, options Options, sourceMirror, packHash string, partNumber uint32) (RepairResult, error) {
	result := RepairResult{PackHash: packHash, PartNumber: partNumber}
	run, err := openRuntime(options, true)
	if err != nil {
		return result, err
	}
	defer func() { _ = run.close() }()
	pending, err := run.loadTransaction()
	if err != nil {
		return result, err
	}
	extending := pending != nil && pending.Kind == "repair" && pending.LocalCommit == "" && !pending.Resetting
	if pending != nil && !pending.PushAttempted && !extending {
		return result, fmt.Errorf("finish or reset the staged transaction before repair")
	}
	head, history, err := run.validatedHead(pending == nil || !pending.LocalAccepted)
	if err != nil {
		return result, err
	}
	defer func() { _ = history.Close() }()
	if err := run.requirePinnedMirrors(head.State); err != nil {
		return result, err
	}
	oldPart, found, err := repository.FindPackPart(head.State, packHash, partNumber)
	if err != nil {
		return result, err
	}
	if !found {
		return result, fmt.Errorf("pack %s part %d is absent from HEAD", packHash, partNumber)
	}
	result.OldObjectID = oldPart.ObjectID
	if extending {
		if err := run.walkDataParts(pending, func(_ uint64, part stagedDataPart) error {
			if part.Entry.PackHash == packHash && part.Entry.PartNumber == partNumber {
				result.NewObjectID = part.Entry.ObjectID
			}
			return nil
		}); err != nil {
			return result, err
		}
		if result.NewObjectID != "" {
			committed, err := run.commitTransaction(ctx, pending)
			result.CommitID, result.CompleteMirrors = committed.CommitID, committed.CompleteMirrors
			return result, err
		}
	}
	sourcePin, ok := run.mirror(sourceMirror)
	if !ok {
		return result, fmt.Errorf("unknown source mirror %q", sourceMirror)
	}
	source, err := run.client(ctx, sourcePin)
	if err != nil {
		return result, err
	}
	oldKey, _ := format.ObjectKey(oldPart.PartHash, oldPart.ObjectID)
	expected := objectstore.Object{Size: oldPart.PartSize, BLAKE2b: oldPart.PartHash, SHA256: oldPart.PartSHA256, MD5: oldPart.PartMD5}
	if err := requireWorkspaceCapacity(run.options.statePath(), oldPart.PartSize, 1, run.options.SpaceReserveBytes); err != nil {
		return result, fmt.Errorf("stage repair part: %w", err)
	}
	// Do not touch a pending transaction's payloads until healthy source bytes
	// have been obtained and its metadata chain is independently recoverable.
	sourceDirectory := filepath.Join(run.options.statePath(), "repair-source")
	if err := removeTreeIfPresent(sourceDirectory); err != nil {
		return result, err
	}
	if err := ensurePrivateDirectory(sourceDirectory); err != nil {
		return result, err
	}
	defer func() { _ = removeTreeIfPresent(sourceDirectory) }()
	file, err := os.CreateTemp(sourceDirectory, ".repair-source-*")
	if err != nil {
		return result, err
	}
	sourcePath := file.Name()
	defer func() { _ = file.Close(); _ = os.Remove(sourcePath) }()
	if err := source.GetVerified(ctx, oldKey, expected, file); err != nil {
		if observationErr := run.observeDataFailure(sourceMirror, oldKey, err); observationErr != nil {
			return result, observationErr
		}
		return result, fmt.Errorf("source mirror lacks healthy repair bytes: %w", err)
	}
	if err := file.Sync(); err != nil {
		return result, err
	}
	if err := file.Close(); err != nil {
		return result, err
	}
	txn := newTransaction("repair", head.CommitID, run.options.Now().UTC())
	if extending {
		txn = *pending
	} else {
		if err := run.prepareForwardRepair(ctx, pending); err != nil {
			return result, err
		}
		if err := run.prepareTransactionFiles(); err != nil {
			return result, err
		}
		if err := run.stageCandidateState(&txn, head.State); err != nil {
			return result, err
		}
	}
	newID, err := randomHex(16)
	if err != nil {
		return result, err
	}
	result.NewObjectID = newID
	partRelative := "repair-part-" + newID
	partPath := filepath.Join(run.options.transactionFilesPath(), partRelative)
	if err := os.Rename(sourcePath, partPath); err != nil {
		return result, err
	}
	if err := syncDirectory(run.options.transactionFilesPath()); err != nil {
		return result, err
	}
	if err := run.rewriteCandidatePackObjectID(&txn, oldPart, newID); err != nil {
		return result, err
	}
	newPart := oldPart
	newPart.ObjectID = newID
	candidate, err := run.loadCandidateState(&txn)
	if err != nil {
		return result, err
	}
	kind, err := repository.ValidateTransition(head.State, candidate)
	if err != nil || kind != repository.TransitionRepair {
		return result, fmt.Errorf("repair candidate is not a valid relocation transition: %w", err)
	}
	if err := run.rewriteDataParts(&txn, txn.DataPartCount, stagedDataPart{Entry: newPart, RelativePath: partRelative}); err != nil {
		return result, err
	}
	for _, progress := range txn.Mirrors {
		progress.DataComplete = false
		progress.RevisionComplete = false
	}
	if err := run.saveTransaction(&txn); err != nil {
		return result, err
	}
	if err := run.checkpoint("forward-repair-candidate-staged"); err != nil {
		return result, err
	}
	committed, err := run.commitTransaction(ctx, &txn)
	if err != nil {
		return result, err
	}
	result.CommitID, result.CompleteMirrors = committed.CommitID, committed.CompleteMirrors
	return result, nil
}
