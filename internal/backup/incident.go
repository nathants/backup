package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func conclusiveObjectFailure(err error) bool {
	return errors.Is(err, objectstore.ErrCorrupt) || errors.Is(err, objectstore.ErrMissing)
}

// A new incident invalidates all earlier positive evidence in the same atomic
// write as the quarantine. Reobserving an already quarantined mirror does not
// repeatedly revoke fresh evidence for surviving mirrors.
func (run *runtime) quarantine(repositoryUUID, name string) (returnErr error) {
	defer func() { returnErr = incidentStateFailure(returnErr) }()
	ledger, err := run.loadLedger(repositoryUUID)
	if err != nil {
		return err
	}
	if ledger.Quarantined[name] {
		return nil
	}
	if ledger.Incident == ^uint64(0) {
		return fmt.Errorf("integrity incident counter exhausted")
	}
	ledger.Incident++
	ledger.Quarantined[name] = true
	clear(ledger.Mirrors)
	if err := run.saveLedger(ledger); err != nil {
		return fmt.Errorf("persist mirror quarantine: %w", err)
	}
	return run.reportf("INTEGRITY INCIDENT: mirror %s quarantined; ordinary backups paused until fresh verification establishes a complete current mirror\n", name)
}

func stateHasObject(state repository.State, key string) (bool, error) {
	found := false
	err := state.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		candidate, err := format.ObjectKey(part.PartHash, part.ObjectID)
		if err != nil {
			return err
		}
		found = found || candidate == key
		return nil
	})
	return found, err
}

// Only current physical mappings affect writer eligibility. In particular an
// explicit historical restore of a superseded corrupt object cannot re-pause
// an already repaired repository. Absence on a lagging mirror is not data loss.
func (run *runtime) observeDataFailure(name, key string, failure error) (returnErr error) {
	defer func() { returnErr = incidentStateFailure(returnErr) }()
	if !strings.HasPrefix(key, "objects/") {
		return nil
	}
	if !conclusiveObjectFailure(failure) {
		return nil
	}
	head, history, err := run.validatedHead(false)
	if err != nil {
		return err
	}
	defer func() { _ = history.Close() }()
	required, err := stateHasObject(head.State, key)
	if err != nil || !required {
		return err
	}
	ledger, err := run.loadLedger(head.State.Format.RepositoryUUID)
	if err != nil {
		return err
	}
	if ledger.Quarantined[name] {
		return nil
	}
	if errors.Is(failure, objectstore.ErrMissing) && !errors.Is(failure, objectstore.ErrCorrupt) {
		txn, err := run.loadTransaction()
		if err != nil {
			return err
		}
		acknowledged := false
		if txn != nil && txn.LocalCommit == head.CommitID {
			if progress := txn.Mirrors[name]; progress != nil {
				acknowledged = progress.DataComplete
			}
			acknowledged = acknowledged || txn.Capture != nil && txn.Capture.Mirrors[name]
		}
		if !acknowledged {
			prior := ledger.Mirrors[name]
			if prior == "" {
				return nil
			}
			known, err := history.ResolveRevision(prior)
			if err != nil {
				return err
			}
			required, err = stateHasObject(known.State, key)
			if err != nil || !required {
				return err
			}
		}
	}
	return run.quarantine(head.State.Format.RepositoryUUID, name)
}

func (run *runtime) auditData(ctx context.Context, client *objectstore.Client, name string, state repository.State) error {
	return state.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		key, err := format.ObjectKey(part.PartHash, part.ObjectID)
		if err != nil {
			return err
		}
		expected := objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5}
		if err := client.Audit(ctx, key, expected); err != nil {
			if observationErr := run.observeDataFailure(name, key, err); observationErr != nil {
				return observationErr
			}
			return fmt.Errorf("data part %s: %w", key, err)
		}
		return nil
	})
}

func (run *runtime) auditChain(ctx context.Context, client *objectstore.Client, name string, history *repository.History, target int, txn *transaction) error {
	selected, err := history.CommitID(target)
	if err != nil {
		return incidentStateFailure(err)
	}
	identity, err := history.GenesisFormat()
	if err != nil {
		return incidentStateFailure(err)
	}
	uuid := identity.RepositoryUUID
	failure := auditManifestChain(ctx, client, history, target, uuid, txn, nil)
	if !conclusiveObjectFailure(failure) {
		return failure
	}
	if errors.Is(failure, objectstore.ErrCorrupt) {
		if err := run.quarantine(uuid, name); err != nil {
			return err
		}
		return failure
	}
	ledger, err := run.loadLedger(uuid)
	if err != nil {
		return incidentStateFailure(err)
	}
	if txn != nil && txn.LocalCommit == selected && txn.Metadata != nil {
		if progress := txn.Mirrors[name]; progress != nil && progress.MetadataManifest {
			if err := run.quarantine(uuid, name); err != nil {
				return err
			}
			return failure
		}
	}
	if ledger.Quarantined[name] || ledger.Mirrors[name] == "" {
		return failure
	}
	knownIndex, found, err := history.IndexOf(ledger.Mirrors[name])
	if err != nil {
		return incidentStateFailure(err)
	}
	if !found {
		return incidentStateFailure(fmt.Errorf("completion ledger is outside validated history"))
	}
	// A pending/new edge may simply be lagging. Check the previously completed
	// chain before interpreting an absent representation as lost recovery data.
	knownFailure := failure
	if knownIndex != target {
		knownFailure = auditManifestChain(ctx, client, history, knownIndex, uuid, txn, nil)
	}
	if conclusiveObjectFailure(knownFailure) {
		if err := run.quarantine(uuid, name); err != nil {
			return incidentStateFailure(err)
		}
	}
	return failure
}

func (run *runtime) auditMirror(ctx context.Context, mirror localconfig.Mirror, history *repository.History, selected repository.ValidatedCommit, txn *transaction) error {
	reader, err := run.client(ctx, mirror)
	if err != nil {
		return err
	}
	index, found, err := history.IndexOf(selected.CommitID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("audit revision is outside validated history")
	}
	// Check data even when the last metadata edge is still awaiting publication.
	dataErr := run.auditData(ctx, reader, mirror.Canonical.Name, selected.State)
	if isIncidentStateError(dataErr) {
		return dataErr
	}
	chainErr := run.auditChain(ctx, reader, mirror.Canonical.Name, history, index, txn)
	return errors.Join(dataErr, chainErr)
}

func (run *runtime) recordVerified(uuid, name, commit string) error {
	ledger, err := run.loadLedger(uuid)
	if err != nil {
		return err
	}
	delete(ledger.Quarantined, name)
	ledger.Mirrors[name] = commit
	return run.saveLedger(ledger)
}

func (ledger completionLedger) eligible(name, commit string) bool {
	return commit != "" && !ledger.Quarantined[name] && ledger.Mirrors[name] == commit
}

func (run *runtime) requireBackupEligibility(txn *transaction, ledger completionLedger) error {
	if txn.Kind == "repair" || txn.Kind == "genesis" && ledger.Incident == 0 {
		return nil
	}
	if ledger.ForwardRepair != "" {
		return fmt.Errorf("published revision %s requires forward repair before ordinary backups", ledger.ForwardRepair)
	}
	eligible := false
	for _, mirror := range run.config.Mirrors {
		name := mirror.Canonical.Name
		eligible = eligible || ledger.eligible(name, txn.BaseCommit) || txn.LocalCommit != "" && ledger.eligible(name, txn.LocalCommit)
	}
	if !eligible {
		return fmt.Errorf("ordinary backups paused: no mirror is durably known complete; run verify, then repair or sync as needed")
	}
	if len(ledger.Quarantined) != 0 {
		return run.reportf("DEGRADED REDUNDANCY: quarantined mirrors %q remain excluded until repaired and successfully verified\n", sortedMirrorNames(ledger.Quarantined))
	}
	return nil
}

func (run *runtime) revalidateCapture(ctx context.Context, txn *transaction, ledger completionLedger) error {
	eligible := make(map[string]bool)
	for _, mirror := range run.config.Mirrors {
		name := mirror.Canonical.Name
		if !txn.Capture.Mirrors[name] || !ledger.eligible(name, txn.BaseCommit) {
			continue
		}
		if txn.Incident != ledger.Incident {
			reader, err := run.client(ctx, mirror)
			if err != nil {
				continue
			}
			if err := run.auditCapturedParts(ctx, reader, txn); err != nil {
				if err := run.reportf("mirror %s captured progress requires repair/reset: %s\n", name, terminalEscape(err.Error())); err != nil {
					return err
				}
				continue
			}
		}
		eligible[name] = true
	}
	if len(eligible) == 0 {
		return fmt.Errorf("no eligible mirror retains verified captured progress; verify mirrors or reset the unpublished capture")
	}
	txn.Capture.Mirrors = eligible
	txn.Incident = ledger.Incident
	return run.saveTransaction(txn)
}

func (run *runtime) auditCapturedParts(ctx context.Context, client *objectstore.Client, txn *transaction) error {
	_, _, paths, err := run.captureSegmentInputPaths(txn, false)
	if err != nil {
		return err
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		auditErr := format.WalkPacks(file, format.DefaultLimits(), func(part format.PackEntry) error {
			key, err := format.ObjectKey(part.PartHash, part.ObjectID)
			if err != nil {
				return err
			}
			return client.Audit(ctx, key, objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5})
		})
		closeErr := file.Close()
		if err := errors.Join(auditErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

// Repair proves the CANDIDATE data plus the BASE metadata chain, never a
// corrupt base data catalog. An interrupted ordinary candidate likewise cannot
// reuse pre-incident acknowledgements without fresh checksum evidence.
func (run *runtime) revalidateCandidate(ctx context.Context, txn *transaction, candidate repository.State, ledger completionLedger) error {
	revision := txn.BaseCommit
	if txn.LocalCommit != "" {
		revision = txn.LocalCommit
	}
	history, err := run.historyValidator().ValidateHistory(revision)
	if err != nil {
		return err
	}
	defer func() { _ = history.Close() }()
	for _, mirror := range run.config.Mirrors {
		name := mirror.Canonical.Name
		progress := txn.progress(name)
		progress.DataComplete = false
		progress.RevisionComplete = false
		if txn.Kind != "repair" && !ledger.eligible(name, txn.BaseCommit) && !(txn.LocalCommit != "" && ledger.eligible(name, txn.LocalCommit)) {
			continue
		}
		reader, err := run.client(ctx, mirror)
		if err == nil {
			err = run.auditData(ctx, reader, name, candidate)
		}
		if err == nil {
			baseIndex, found, findErr := history.IndexOf(txn.BaseCommit)
			if findErr != nil {
				return findErr
			}
			if !found {
				return fmt.Errorf("candidate base is outside validated history")
			}
			err = run.auditChain(ctx, reader, name, history, baseIndex, txn)
		}
		if err != nil {
			if isIncidentStateError(err) {
				return err
			}
			if err := run.reportf("mirror %s candidate audit failed: %s\n", name, terminalEscape(err.Error())); err != nil {
				return err
			}
			continue
		}
		progress.DataComplete = true
		progress.DataPartCursor = txn.DataPartCount
		if txn.Capture != nil {
			txn.Capture.Mirrors[name] = true
		}
	}
	latest, err := run.loadLedger(candidate.Format.RepositoryUUID)
	if err != nil {
		return err
	}
	if latest.Incident != ledger.Incident {
		return fmt.Errorf("new integrity incident during candidate audit; verify healthy mirrors before retrying")
	}
	if !hasDataComplete(txn) {
		return fmt.Errorf("no individual mirror passed fresh candidate-data and base-metadata verification")
	}
	txn.Incident = ledger.Incident
	return run.saveTransaction(txn)
}

// Local incident-state failures must abort the operation, not be counted as
// just another unavailable mirror when another mirror passes.
type incidentStateError struct{ cause error }

func (err *incidentStateError) Error() string {
	return "integrity operational state: " + err.cause.Error()
}
func (err *incidentStateError) Unwrap() error { return err.cause }
func isIncidentStateError(err error) bool {
	var stateErr *incidentStateError
	return errors.As(err, &stateErr)
}
func incidentStateFailure(err error) error {
	if err == nil || isIncidentStateError(err) {
		return err
	}
	return &incidentStateError{cause: err}
}

func (run *runtime) observeSyncDestination(ctx context.Context, mirror localconfig.Mirror, history *repository.History, selected repository.ValidatedCommit, txn *transaction) error {
	err := run.auditMirror(ctx, mirror, history, selected, txn)
	if isIncidentStateError(err) {
		return err
	}
	return nil
}
