package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/metadatachain"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func Commit(ctx context.Context, options Options) (SnapshotResult, error) {
	run, err := openRuntime(options, true)
	if err != nil {
		return SnapshotResult{}, err
	}
	defer run.close()
	txn, err := run.loadTransaction()
	if err != nil {
		return SnapshotResult{}, err
	}
	if txn == nil {
		head, history, err := run.validatedHead(false)
		if err != nil {
			return SnapshotResult{}, err
		}
		defer history.Close()
		return SnapshotResult{CommitID: head.CommitID, NoChanges: true}, nil
	}
	if txn.Plan != nil && len(txn.CandidateFiles) == 0 {
		history, err := run.historyValidator().ValidateHistory(txn.BaseCommit)
		if err != nil {
			return SnapshotResult{}, err
		}
		base, err := history.Tip()
		history.Close()
		if err != nil {
			return SnapshotResult{}, err
		}
		noChanges, err := run.capturePlan(ctx, txn, base.State)
		if err != nil {
			return SnapshotResult{}, err
		}
		if noChanges {
			if err := run.clearTransactionFiles(); err != nil {
				return SnapshotResult{}, err
			}
			return SnapshotResult{CommitID: txn.BaseCommit, NoChanges: true}, nil
		}
	}
	return run.commitTransaction(ctx, txn)
}

func (run *runtime) commitTransaction(ctx context.Context, txn *transaction) (SnapshotResult, error) {
	if txn.Resetting {
		return SnapshotResult{}, fmt.Errorf("transaction reset is in progress; run reset to finish it")
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		return SnapshotResult{}, err
	}
	if err := run.requirePinnedMirrors(candidate); err != nil {
		return SnapshotResult{}, err
	}
	var baseState repository.State
	var sequence uint64
	transition := repository.TransitionInvalid
	if txn.BaseCommit == "" {
		if err := candidate.ValidateGenesis(); err != nil {
			return SnapshotResult{}, err
		}
		if txn.Kind != "genesis" {
			return SnapshotResult{}, fmt.Errorf("genesis candidate has transaction kind %q", txn.Kind)
		}
	} else {
		history, err := run.historyValidator().ValidateHistory(txn.BaseCommit)
		if err != nil {
			return SnapshotResult{}, err
		}
		base, tipErr := history.Tip()
		sequence = uint64(history.Len())
		history.Close()
		if tipErr != nil {
			return SnapshotResult{}, tipErr
		}
		baseState = base.State
		transition, err = repository.ValidateTransition(baseState, candidate)
		if err != nil {
			return SnapshotResult{}, err
		}
		expectedKind := "ordinary"
		if transition == repository.TransitionRepair {
			expectedKind = "repair"
		}
		if txn.Kind != expectedKind {
			return SnapshotResult{}, fmt.Errorf("transaction kind %q disagrees with candidate transition %q", txn.Kind, expectedKind)
		}
	}
	if err := run.validateStagedDataSet(*txn, baseState, candidate, transition); err != nil {
		return SnapshotResult{}, err
	}
	if err := validateStagedMetadataIdentity(*txn, candidate, sequence); err != nil {
		return SnapshotResult{}, err
	}
	if txn.LocalCommit != "" {
		validated, err := (repository.Validator{Repo: run.repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(txn.LocalCommit)
		if err != nil {
			return SnapshotResult{}, fmt.Errorf("validate recorded local commit: %w", err)
		}
		local, tipErr := validated.Tip()
		validated.Close()
		if tipErr != nil {
			return SnapshotResult{}, tipErr
		}
		if local.ParentID != txn.BaseCommit || !local.State.Equal(candidate) {
			return SnapshotResult{}, fmt.Errorf("recorded local commit disagrees with the durable candidate")
		}
	}
	ledger, err := run.loadLedger(candidate.Format.RepositoryUUID)
	if err != nil {
		return SnapshotResult{}, err
	}
	for _, mirror := range run.config.Mirrors {
		progress := txn.progress(mirror.Canonical.Name)
		eligible := txn.BaseCommit == "" || ledger.Mirrors[mirror.Canonical.Name] == txn.BaseCommit
		if !eligible {
			progress.DataComplete = false
			progress.RevisionComplete = false
		} else if txn.Capture != nil {
			progress.DataComplete = txn.Capture.Mirrors[mirror.Canonical.Name]
			if !progress.DataComplete {
				progress.RevisionComplete = false
			}
		} else if len(txn.DataParts) == 0 {
			progress.DataComplete = true
		}
	}
	if txn.LocalCommit == "" {
		rotated, err := run.uploadDataParts(ctx, txn, ledger)
		if err != nil {
			return SnapshotResult{}, err
		}
		if rotated {
			return SnapshotResult{}, fmt.Errorf("an ambiguous data upload was assigned a fresh immutable key; retry commit")
		}
		if !hasDataComplete(txn) {
			return SnapshotResult{}, fmt.Errorf("no individual mirror has the complete candidate data revision")
		}
		commit, err := run.repo.CreateCommitState(txn.BaseCommit, candidate, commitMessage(txn.Kind, sequence))
		if err != nil {
			return SnapshotResult{}, err
		}
		txn.LocalCommit = commit
		if err := run.saveTransaction(txn); err != nil {
			return SnapshotResult{}, err
		}
		if err := run.checkpoint("local-commit-recorded"); err != nil {
			return SnapshotResult{}, err
		}
	}
	if !txn.LocalAccepted {
		head, headErr := run.repo.Head()
		if headErr == nil && head == txn.LocalCommit {
			txn.LocalAccepted = true
			if err := run.saveTransaction(txn); err != nil {
				return SnapshotResult{}, err
			}
		} else {
			if txn.BaseCommit != "" && (headErr != nil || head != txn.BaseCommit) {
				return SnapshotResult{}, fmt.Errorf("local metadata head changed while accepting revision")
			}
			if err := run.repo.ApplyCommit(txn.LocalCommit, txn.BaseCommit); err != nil {
				return SnapshotResult{}, err
			}
			txn.LocalAccepted = true
			if err := run.saveTransaction(txn); err != nil {
				return SnapshotResult{}, err
			}
		}
		if err := run.checkpoint("local-commit-accepted"); err != nil {
			return SnapshotResult{}, err
		}
	}
	if txn.Metadata == nil {
		metadataStage := filepath.Join(run.options.transactionFilesPath(), "metadata")
		if err := removeTreeNoFollow(metadataStage); err != nil && !errors.Is(err, os.ErrNotExist) {
			return SnapshotResult{}, fmt.Errorf("discard incomplete metadata staging: %w", err)
		}
		if err := ensurePrivateDirectory(metadataStage); err != nil {
			return SnapshotResult{}, err
		}
		partSize, ciphertextBudget, err := boundedMetadataStaging(metadataStage, run.options.MetadataPartSize, run.options.SpaceReserveBytes)
		if err != nil {
			return SnapshotResult{}, err
		}
		result, err := metadatachain.Build(run.repo, candidate.Format.RepositoryUUID, txn.BaseCommit, txn.LocalCommit, sequence, candidate.PublicKeys, metadataStage, partSize, ciphertextBudget)
		if err != nil {
			return SnapshotResult{}, err
		}
		partsDirectory, err := run.stagedRelativePath(metadataStage)
		if err != nil {
			return SnapshotResult{}, err
		}
		for index, part := range result.Parts {
			destination := filepath.Join(metadataStage, fmt.Sprintf("part-%08d", index))
			if err := os.Rename(part.Path, destination); err != nil {
				return SnapshotResult{}, err
			}
		}
		manifestDestination := filepath.Join(metadataStage, "manifest-"+result.ManifestHash)
		if err := os.Rename(result.ManifestPath, manifestDestination); err != nil {
			return SnapshotResult{}, err
		}
		if err := syncDirectory(metadataStage); err != nil {
			return SnapshotResult{}, err
		}
		manifestRelative, err := run.stagedRelativePath(manifestDestination)
		if err != nil {
			return SnapshotResult{}, err
		}
		staged := &stagedMetadata{
			Manifest: result.Manifest, ManifestHash: result.ManifestHash, PartsDirectory: partsDirectory,
			ManifestObjectID: result.ManifestObjectID, ManifestRelativePath: manifestRelative,
		}
		txn.Metadata = staged
		if err := run.saveTransaction(txn); err != nil {
			return SnapshotResult{}, err
		}
		if err := run.checkpoint("metadata-staged"); err != nil {
			return SnapshotResult{}, err
		}
	}
	if !txn.PushConfirmed {
		if err := run.confirmOrPush(ctx, txn); err != nil {
			return SnapshotResult{}, err
		}
	}
	for name, commit := range ledger.Mirrors {
		if commit == txn.LocalCommit {
			progress := txn.progress(name)
			progress.DataComplete = true
			progress.RevisionComplete = true
		}
	}
	metadataUploadErr := run.uploadMetadata(ctx, txn, &ledger)
	var unavailable *metadataUploadUnavailable
	if metadataUploadErr != nil && !errors.As(metadataUploadErr, &unavailable) {
		return SnapshotResult{}, metadataUploadErr
	}
	if !hasRevisionComplete(txn) {
		if unavailable != nil && len(unavailable.uncertainKeys) != 0 {
			if rotated, err := run.rotateMetadataRepresentation(txn, unavailable.uncertainKeys); err != nil {
				return SnapshotResult{}, err
			} else if rotated {
				return SnapshotResult{}, fmt.Errorf("ambiguous metadata uploads were assigned fresh immutable keys; retry commit")
			}
		}
		if unavailable != nil {
			return SnapshotResult{}, fmt.Errorf("no individual mirror has a complete metadata chain through revision %s: %w", txn.LocalCommit, unavailable)
		}
		return SnapshotResult{}, fmt.Errorf("no individual mirror has a complete metadata chain through revision %s", txn.LocalCommit)
	}
	complete := make(map[string]bool)
	lagging := make(map[string]bool)
	for _, mirror := range run.config.Mirrors {
		if txn.progress(mirror.Canonical.Name).RevisionComplete {
			complete[mirror.Canonical.Name] = true
		} else {
			lagging[mirror.Canonical.Name] = true
		}
	}
	result := SnapshotResult{CommitID: txn.LocalCommit, CompleteMirrors: sortedMirrorNames(complete), LaggingMirrors: sortedMirrorNames(lagging)}
	if err := run.clearTransactionFiles(); err != nil {
		return SnapshotResult{}, err
	}
	if err := run.checkpoint("transaction-cleared"); err != nil {
		return SnapshotResult{}, err
	}
	return result, nil
}

func commitMessage(kind string, sequence uint64) string {
	return fmt.Sprintf("backup %s revision %d", kind, sequence)
}

func (run *runtime) validateStagedDataSet(txn transaction, base, candidate repository.State, transition repository.TransitionKind) error {
	if transition == repository.TransitionOrdinary && txn.Capture != nil {
		if txn.Plan == nil || txn.Capture.NextPlan != txn.Plan.Entries || len(txn.Capture.Mirrors) == 0 || len(txn.DataParts) != 0 {
			return fmt.Errorf("captured ordinary revision has incomplete or duplicated data progress")
		}
		if err := run.validateCapturedCandidate(&txn, base, candidate); err != nil {
			return fmt.Errorf("validate captured candidate derivation: %w", err)
		}
		return nil
	}
	expected := make(map[format.PackEntry]bool, len(txn.DataParts))
	for _, part := range txn.DataParts {
		if expected[part.Entry] {
			return fmt.Errorf("staged data parts contain a duplicate pack row")
		}
		expected[part.Entry] = true
	}
	if err := repository.WalkChangedPacks(base, candidate, transition, func(entry format.PackEntry) error {
		if !expected[entry] {
			return fmt.Errorf("staged data parts do not exactly match the changed candidate pack rows")
		}
		delete(expected, entry)
		return nil
	}); err != nil {
		return err
	}
	if len(expected) != 0 {
		return fmt.Errorf("staged data parts do not exactly match the changed candidate pack rows")
	}
	return nil
}

func metadataPartRelative(metadata *stagedMetadata, index int) (string, error) {
	if metadata == nil || index < 0 || index >= len(metadata.Manifest.Parts) || metadata.PartsDirectory == "" {
		return "", fmt.Errorf("invalid staged metadata part position")
	}
	return filepath.Join(metadata.PartsDirectory, fmt.Sprintf("part-%08d", index)), nil
}

func validateStagedMetadataIdentity(txn transaction, candidate repository.State, sequence uint64) error {
	if txn.Metadata == nil {
		return nil
	}
	manifest := txn.Metadata.Manifest
	if manifest.RepositoryUUID != candidate.Format.RepositoryUUID || manifest.Sequence != sequence || manifest.TipCommit != txn.LocalCommit {
		return fmt.Errorf("staged metadata manifest disagrees with the candidate repository identity, sequence, or tip")
	}
	if txn.BaseCommit == "" {
		if manifest.Kind != format.BundleFull || manifest.BaseCommit != "-" {
			return fmt.Errorf("genesis metadata manifest is not an exact full bundle")
		}
	} else if manifest.Kind != format.BundleIncremental || manifest.BaseCommit != txn.BaseCommit {
		return fmt.Errorf("incremental metadata manifest does not name the exact candidate parent")
	}
	return nil
}

func hasDataComplete(txn *transaction) bool {
	for _, progress := range txn.Mirrors {
		if progress.DataComplete {
			return true
		}
	}
	return false
}

func hasRevisionComplete(txn *transaction) bool {
	for _, progress := range txn.Mirrors {
		if progress.RevisionComplete {
			return true
		}
	}
	return false
}

func (run *runtime) uploadDataParts(ctx context.Context, txn *transaction, ledger completionLedger) (bool, error) {
	if len(txn.DataParts) == 0 {
		for _, mirror := range run.config.Mirrors {
			eligible := txn.BaseCommit == "" || ledger.Mirrors[mirror.Canonical.Name] == txn.BaseCommit
			complete := eligible
			if txn.Capture != nil {
				complete = complete && txn.Capture.Mirrors[mirror.Canonical.Name]
			}
			txn.progress(mirror.Canonical.Name).DataComplete = complete
		}
		if err := run.saveTransaction(txn); err != nil {
			return false, err
		}
		if err := run.checkpoint("data-revision-acknowledged"); err != nil {
			return false, err
		}
		return false, nil
	}
	for partIndex := range txn.DataParts {
		part := &txn.DataParts[partIndex]
		key, err := format.ObjectKey(part.Entry.PartHash, part.Entry.ObjectID)
		if err != nil {
			return false, err
		}
		expected := objectstore.Object{Size: part.Entry.PartSize, BLAKE2b: part.Entry.PartHash, SHA256: part.Entry.PartSHA256, MD5: part.Entry.PartMD5}
		acknowledged := false
		uncertain := false
		for _, mirror := range run.config.Mirrors {
			progress := txn.progress(mirror.Canonical.Name)
			if progress.DataPartCursor > uint64(partIndex) {
				acknowledged = true
				continue
			}
			if progress.DataPartCursor < uint64(partIndex) {
				continue
			}
			writer, err := run.writer(ctx, mirror)
			if err != nil {
				if reportErr := run.reportf("mirror %s data upload unavailable: %s\n", mirror.Canonical.Name, terminalEscape(err.Error())); reportErr != nil {
					return false, reportErr
				}
				continue
			}
			result := run.putStaged(ctx, writer, key, part.RelativePath, expected)
			if result.Disposition == objectstore.CreateAcknowledged || (result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous) && run.auditObject(ctx, mirror, key, expected) == nil {
				if err := run.checkpoint("data-object-created-before-ack"); err != nil {
					return false, err
				}
				progress.DataPartCursor = uint64(partIndex) + 1
				acknowledged = true
				if err := run.saveTransaction(txn); err != nil {
					return false, err
				}
				if err := run.checkpoint("data-object-acknowledged"); err != nil {
					return false, err
				}
				continue
			}
			if result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous {
				uncertain = true
			}
			if err := run.reportf("mirror %s did not acknowledge data object %s: %s\n", mirror.Canonical.Name, key, terminalEscape(errorText(result.Err))); err != nil {
				return false, err
			}
		}
		if !acknowledged && uncertain {
			if err := run.rotateDataPart(txn, partIndex); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	for _, mirror := range run.config.Mirrors {
		progress := txn.progress(mirror.Canonical.Name)
		eligible := txn.BaseCommit == "" || ledger.Mirrors[mirror.Canonical.Name] == txn.BaseCommit
		complete := eligible && progress.DataPartCursor == uint64(len(txn.DataParts))
		progress.DataComplete = complete
	}
	if err := run.saveTransaction(txn); err != nil {
		return false, err
	}
	if err := run.checkpoint("data-revision-acknowledged"); err != nil {
		return false, err
	}
	return false, nil
}

func (run *runtime) auditObject(ctx context.Context, mirror localconfig.Mirror, key string, expected objectstore.Object) error {
	reader, err := run.reader(ctx, mirror)
	if err != nil {
		return err
	}
	return reader.Audit(ctx, key, expected)
}

func (run *runtime) rotateDataPart(txn *transaction, index int) error {
	if txn.LocalCommit != "" {
		return fmt.Errorf("cannot relocate staged data after creating the metadata commit")
	}
	part := &txn.DataParts[index]
	oldEntry := part.Entry
	newID, err := randomHex(16)
	if err != nil {
		return err
	}
	if err := run.rewriteCandidatePackObjectID(txn, oldEntry, newID); err != nil {
		return err
	}
	part.Entry.ObjectID = newID
	// The data-part descriptor and packs catalog are published under new
	// content-addressed staging names before the transaction control record is
	// replaced. A crash can therefore leave only harmless unreferenced files,
	// never old references whose bytes were overwritten in place.
	txn.DataPartsFile = stagedFileRef{}
	for _, progress := range txn.Mirrors {
		if progress.DataPartCursor > uint64(index) {
			return fmt.Errorf("cannot relocate a data part already acknowledged by a mirror")
		}
		progress.DataComplete = false
	}
	if err := run.saveTransaction(txn); err != nil {
		return err
	}
	return run.checkpoint("data-object-relocated")
}

func (run *runtime) confirmOrPush(_ context.Context, txn *transaction) error {
	if txn.PushAttempted {
		if tip, history, err := run.remoteHistory(); err == nil {
			_, published, findErr := history.IndexOf(txn.LocalCommit)
			history.Close()
			if findErr != nil {
				return findErr
			}
			if published {
				txn.PushConfirmed = true
				if err := run.saveTransaction(txn); err != nil {
					return err
				}
				if tip != txn.LocalCommit {
					if err := run.checkpoint("git-push-confirmed-by-descendant"); err != nil {
						return err
					}
				}
				return run.checkpoint("git-push-confirmed")
			}
		}
	}
	txn.PushAttempted = true
	if err := run.saveTransaction(txn); err != nil {
		return err
	}
	if err := run.checkpoint("git-push-intent-recorded"); err != nil {
		return err
	}
	if err := run.repo.Push(txn.LocalCommit, txn.BaseCommit); err != nil {
		return err
	}
	if err := run.checkpoint("git-push-returned"); err != nil {
		return err
	}
	tip, err := run.remoteTip()
	if err != nil {
		return fmt.Errorf("confirm metadata push: %w", err)
	}
	if tip != txn.LocalCommit {
		return fmt.Errorf("metadata remote resolved to %s after pushing %s", tip, txn.LocalCommit)
	}
	txn.PushConfirmed = true
	if err := run.saveTransaction(txn); err != nil {
		return err
	}
	return run.checkpoint("git-push-confirmed")
}

func (run *runtime) remoteHistory() (string, *repository.History, error) {
	if err := run.repo.Fetch(); err != nil {
		return "", nil, err
	}
	history, err := run.historyValidator().ValidateHistory("refs/remotes/origin/" + run.config.Branch)
	if err != nil {
		return "", nil, err
	}
	tip, err := history.Tip()
	if err != nil {
		history.Close()
		return "", nil, err
	}
	return tip.CommitID, history, nil
}

func (run *runtime) remoteTip() (string, error) {
	tip, history, err := run.remoteHistory()
	if history != nil {
		history.Close()
	}
	return tip, err
}

func (run *runtime) uploadMetadata(ctx context.Context, txn *transaction, ledger *completionLedger) error {
	metadata := txn.Metadata
	var lastErr error
	uncertainKeys := make(map[string]bool)
	for _, mirror := range run.config.Mirrors {
		progress := txn.progress(mirror.Canonical.Name)
		if progress.RevisionComplete || !progress.DataComplete {
			continue
		}
		if txn.BaseCommit != "" && ledger.Mirrors[mirror.Canonical.Name] != txn.BaseCommit {
			continue
		}
		writer, err := run.writer(ctx, mirror)
		if err != nil {
			lastErr = err
			continue
		}
		for progress.MetadataPartCursor < uint32(len(metadata.Manifest.Parts)) {
			partIndex := int(progress.MetadataPartCursor)
			part := metadata.Manifest.Parts[partIndex]
			key, err := format.MetadataPartKey(part)
			if err != nil {
				return err
			}
			relative, err := metadataPartRelative(metadata, partIndex)
			if err != nil {
				return err
			}
			expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
			result := run.putStaged(ctx, writer, key, relative, expected)
			if result.Disposition == objectstore.CreateAcknowledged || (result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous) && run.auditObject(ctx, mirror, key, expected) == nil {
				if err := run.checkpoint("metadata-part-created-before-ack"); err != nil {
					return err
				}
				progress.MetadataPartCursor++
				if err := run.saveTransaction(txn); err != nil {
					return err
				}
				if err := run.checkpoint("metadata-part-acknowledged"); err != nil {
					return err
				}
				continue
			}
			lastErr = result.Err
			if lastErr == nil {
				lastErr = fmt.Errorf("metadata part was not acknowledged")
			}
			if result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous {
				uncertainKeys[key] = true
			}
			if err := run.reportf("mirror %s did not acknowledge metadata part %s: %s\n", mirror.Canonical.Name, key, terminalEscape(errorText(result.Err))); err != nil {
				return err
			}
			break
		}
		if progress.MetadataPartCursor != uint32(len(metadata.Manifest.Parts)) {
			continue
		}
		manifestKey, err := format.MetadataManifestKey(metadata.Manifest.TipCommit, metadata.ManifestHash, metadata.ManifestObjectID)
		if err != nil {
			return err
		}
		manifestBytes, err := run.readStaged(metadata.ManifestRelativePath, 1<<20)
		if err != nil {
			return err
		}
		expected := objectstore.HashBytes(manifestBytes)
		if expected.BLAKE2b != metadata.ManifestHash {
			return fmt.Errorf("staged metadata manifest hash changed")
		}
		if !progress.MetadataManifest {
			result := run.putStaged(ctx, writer, manifestKey, metadata.ManifestRelativePath, expected)
			if result.Disposition == objectstore.CreateAcknowledged || (result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous) && run.auditObject(ctx, mirror, manifestKey, expected) == nil {
				if err := run.checkpoint("metadata-manifest-created-before-ack"); err != nil {
					return err
				}
				progress.MetadataManifest = true
			} else {
				lastErr = result.Err
				if lastErr == nil {
					lastErr = fmt.Errorf("metadata manifest was not acknowledged")
				}
				if result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous {
					uncertainKeys[manifestKey] = true
				}
				continue
			}
		}
		progress.RevisionComplete = true
		ledger.Mirrors[mirror.Canonical.Name] = txn.LocalCommit
		if err := run.saveLedger(*ledger); err != nil {
			return err
		}
		if err := run.checkpoint("completion-ledger-recorded"); err != nil {
			return err
		}
		if err := run.saveTransaction(txn); err != nil {
			return err
		}
		if err := run.checkpoint("mirror-revision-acknowledged"); err != nil {
			return err
		}
	}
	if hasRevisionComplete(txn) {
		return nil
	}
	if lastErr != nil {
		return &metadataUploadUnavailable{cause: lastErr, uncertainKeys: uncertainKeys}
	}
	return nil
}

type metadataUploadUnavailable struct {
	cause         error
	uncertainKeys map[string]bool
}

func (err *metadataUploadUnavailable) Error() string {
	return err.cause.Error()
}

func (err *metadataUploadUnavailable) Unwrap() error {
	return err.cause
}

func (run *runtime) rotateMetadataRepresentation(txn *transaction, uncertainKeys map[string]bool) (bool, error) {
	if txn.Metadata == nil || hasRevisionComplete(txn) || len(uncertainKeys) == 0 {
		return false, nil
	}
	metadata := txn.Metadata
	manifestKey, err := format.MetadataManifestKey(metadata.Manifest.TipCommit, metadata.ManifestHash, metadata.ManifestObjectID)
	if err != nil {
		return false, err
	}
	manifestUncertain := uncertainKeys[manifestKey]
	changed := false
	for partIndex := range metadata.Manifest.Parts {
		part := &metadata.Manifest.Parts[partIndex]
		key, _ := format.MetadataPartKey(*part)
		acknowledged := false
		for _, progress := range txn.Mirrors {
			acknowledged = acknowledged || progress.MetadataPartCursor > uint32(partIndex)
		}
		if acknowledged || !uncertainKeys[key] {
			continue
		}
		newID, err := randomHex(16)
		if err != nil {
			return false, err
		}
		part.ObjectID = newID
		changed = true
	}
	manifestAcknowledged := false
	for _, progress := range txn.Mirrors {
		manifestAcknowledged = manifestAcknowledged || progress.MetadataManifest
	}
	if !manifestAcknowledged && (manifestUncertain || changed) {
		newID, err := randomHex(16)
		if err != nil {
			return false, err
		}
		metadata.ManifestObjectID = newID
		changed = true
	}
	if !changed {
		return false, nil
	}
	manifestBytes, err := metadata.Manifest.MarshalText()
	if err != nil {
		return false, err
	}
	identity := objectstore.HashBytes(manifestBytes)
	metadata.ManifestHash = identity.BLAKE2b
	metadata.ManifestRelativePath = filepath.Join(metadata.PartsDirectory, "manifest-"+identity.BLAKE2b)
	manifestPath, err := run.stagedPath(metadata.ManifestRelativePath)
	if err != nil {
		return false, err
	}
	if err := atomicWritePrivate(manifestPath, manifestBytes); err != nil {
		return false, err
	}
	for _, progress := range txn.Mirrors {
		progress.MetadataManifest = false
		progress.RevisionComplete = false
	}
	if err := run.saveTransaction(txn); err != nil {
		return false, err
	}
	if err := run.checkpoint("metadata-representation-relocated"); err != nil {
		return false, err
	}
	return true, nil
}

func errorText(err error) string {
	if err == nil {
		return "unacknowledged response"
	}
	return err.Error()
}
