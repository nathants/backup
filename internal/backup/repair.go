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
	if txn, err := run.loadTransaction(); err != nil {
		return result, err
	} else if txn != nil {
		return result, fmt.Errorf("finish or reset the staged transaction before repair")
	}
	head, history, err := run.validatedHead(true)
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
	sourcePin, ok := run.mirror(sourceMirror)
	if !ok {
		return result, fmt.Errorf("unknown source mirror %q", sourceMirror)
	}
	source, err := run.reader(ctx, sourcePin)
	if err != nil {
		return result, err
	}
	oldKey, _ := format.ObjectKey(oldPart.PartHash, oldPart.ObjectID)
	expected := objectstore.Object{Size: oldPart.PartSize, BLAKE2b: oldPart.PartHash, SHA256: oldPart.PartSHA256, MD5: oldPart.PartMD5}
	if err := run.prepareTransactionFiles(); err != nil {
		return result, err
	}
	if err := requireWorkspaceCapacity(run.options.transactionFilesPath(), oldPart.PartSize, 1, run.options.SpaceReserveBytes); err != nil {
		return result, fmt.Errorf("stage repair part: %w", err)
	}
	partPath := filepath.Join(run.options.transactionFilesPath(), "repair-part")
	file, err := os.OpenFile(partPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return result, err
	}
	if err := source.GetVerified(ctx, oldKey, expected, file); err != nil {
		_ = file.Close()
		return result, fmt.Errorf("source mirror lacks healthy repair bytes: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return result, err
	}
	if err := file.Close(); err != nil {
		return result, err
	}
	newID, err := randomHex(16)
	if err != nil {
		return result, err
	}
	result.NewObjectID = newID
	txn := newTransaction("repair", head.CommitID, run.options.Now().UTC())
	if err := run.stageCandidateState(&txn, head.State); err != nil {
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
	txn.DataParts = []stagedDataPart{{Entry: newPart, RelativePath: "repair-part"}}
	if err := run.saveTransaction(&txn); err != nil {
		return result, err
	}
	committed, err := run.commitTransaction(ctx, &txn)
	if err != nil {
		return result, err
	}
	result.CommitID, result.CompleteMirrors = committed.CommitID, committed.CompleteMirrors
	return result, nil
}
