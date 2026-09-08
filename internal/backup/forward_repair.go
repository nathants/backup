package backup

import (
	"context"
	"errors"
	"fmt"
)

// Explicit forward repair is the only operation that can retire a published
// but unsuccessful transaction. It preserves its exact Git edge on a mirror
// first, without claiming that the damaged data revision is complete.
func (run *runtime) prepareForwardRepair(ctx context.Context, txn *transaction) error {
	if txn == nil {
		return nil
	}
	if !txn.PushAttempted || txn.Metadata == nil {
		return fmt.Errorf("finish or reset the unpublished transaction before repair")
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		return err
	}
	ledger, err := run.loadLedger(candidate.Format.RepositoryUUID)
	if err != nil {
		return err
	}
	if len(ledger.Quarantined) == 0 && ledger.ForwardRepair == "" {
		return fmt.Errorf("pending publication requires commit finalization; forward repair requires an observed integrity incident")
	}
	if err := run.confirmOrPush(ctx, txn); err != nil {
		return err
	}
	tip, history, err := run.remoteHistory()
	if err != nil {
		return err
	}
	defer func() { _ = history.Close() }()
	if tip != txn.LocalCommit {
		return fmt.Errorf("forward repair requires the pending revision to be the exact primary tip")
	}
	head, err := history.Tip()
	if err != nil {
		return err
	}
	if head.State.Format.RepositoryUUID != ledger.RepositoryUUID {
		return fmt.Errorf("forward repair repository identity changed")
	}
	ledger.ForwardRepair = txn.LocalCommit
	if err := run.saveLedger(ledger); err != nil {
		return err
	}
	if err := run.checkpoint("forward-repair-intent-recorded"); err != nil {
		return err
	}
	for _, progress := range txn.Mirrors {
		progress.DataComplete = false
		progress.RevisionComplete = false
		// Re-audit ambiguous/existing metadata with the ordinary conditional path.
		progress.MetadataPartCursor = 0
		progress.MetadataManifest = false
	}
	if err := run.saveTransaction(txn); err != nil {
		return err
	}
	uploadErr := run.uploadMetadata(ctx, txn, &ledger, true)
	var unavailable *metadataUploadUnavailable
	if uploadErr != nil && !errors.As(uploadErr, &unavailable) {
		return uploadErr
	}
	complete := false
	for _, mirror := range run.config.Mirrors {
		reader, err := run.client(ctx, mirror)
		if err == nil {
			err = auditManifestChain(ctx, reader, history, history.Len()-1, head.State.Format.RepositoryUUID, txn, nil)
		}
		if err == nil {
			complete = true
		}
	}
	if !complete {
		if unavailable != nil {
			if _, err := run.rotateMetadataRepresentation(txn, unavailable.uncertainKeys); err != nil {
				return err
			}
		}
		return fmt.Errorf("forward repair retains the pending transaction until its complete metadata chain is verified on one mirror; repair metadata or retry: %s", errorText(uploadErr))
	}
	if err := run.checkpoint("forward-repair-metadata-durable"); err != nil {
		return err
	}
	if err := run.reportf("FORWARD REPAIR: preserving published revision %s and its recovery bundle; damaged revision is NOT reported successful\n", txn.LocalCommit); err != nil {
		return err
	}
	// ForwardRepair remains durable across this cleanup and any interruption
	// before the repair descendant is staged. Ordinary backups remain blocked.
	return run.clearTransactionFiles()
}
