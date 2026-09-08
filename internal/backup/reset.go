package backup

import (
	"fmt"

	"backup/internal/format"
	"backup/internal/repository"
)

// Reset durably abandons a transaction that has not reached the metadata
// remote. Resetting is itself a resumable transaction: once Resetting is
// persisted, commit will not resume publication, and every branch/worktree
// step below is safe to replay after a crash.
func Reset(options Options) error {
	run, err := openRuntime(options, true)
	if err != nil {
		return err
	}
	defer run.close()
	txn, err := run.loadTransaction()
	if err != nil || txn == nil {
		return err
	}
	if err := run.cleanupInterruptedPlaintextSpool(txn); err != nil {
		return fmt.Errorf("clean interrupted plaintext spool: %w", err)
	}
	if txn.Plan != nil && len(txn.CandidateFiles) == 0 {
		return run.clearTransactionFiles()
	}
	if txn.PushConfirmed {
		return fmt.Errorf("published revision %s cannot be reset; run commit to finish mirror completion", txn.LocalCommit)
	}
	if txn.PushAttempted {
		// Seeing the base does not prove that an ambiguous remote write will not
		// become visible later. A different validated descendant does prove that
		// this candidate permanently lost the fast-forward/CAS boundary.
		remote, err := run.remoteTip()
		if err != nil {
			return fmt.Errorf("metadata push was attempted; run commit to resolve publication: %w", err)
		}
		if remote == txn.LocalCommit {
			return fmt.Errorf("published revision %s cannot be reset; run commit to finish mirror completion", txn.LocalCommit)
		}
		if remote == txn.BaseCommit {
			return fmt.Errorf("metadata push was attempted and remains ambiguous; run commit to retry publication")
		}
		if txn.BaseCommit == "" {
			return fmt.Errorf("genesis metadata push was attempted and cannot be safely reset")
		}
		remoteHistory, err := (repository.Validator{Repo: run.repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(remote)
		if err != nil {
			return fmt.Errorf("validate competing metadata history: %w", err)
		}
		defer remoteHistory.Close()
		if _, found, err := remoteHistory.IndexOf(txn.LocalCommit); err != nil {
			return err
		} else if found {
			return fmt.Errorf("published revision %s cannot be reset; run commit to finish mirror completion", txn.LocalCommit)
		}
		_, baseFound, err := remoteHistory.IndexOf(txn.BaseCommit)
		if err != nil {
			return err
		}
		if !baseFound {
			return fmt.Errorf("metadata remote no longer descends from the transaction base; reset is unsafe")
		}
		// The competing descendant makes this candidate permanently stale.
		// Persisting Resetting below is now the durable proof that publication
		// was rejected, so the obsolete attempt marker can be cleared.
		txn.PushAttempted = false
	}
	if !txn.Resetting {
		txn.Resetting = true
		if err := run.saveTransaction(txn); err != nil {
			return err
		}
	}
	return run.finishReset(txn)
}

func (run *runtime) finishReset(txn *transaction) error {
	if txn == nil || !txn.Resetting {
		return fmt.Errorf("reset transaction is not marked in progress")
	}
	if !txn.LocalAccepted {
		if err := run.repo.ApplyCommit(txn.BaseCommit, txn.BaseCommit); err != nil {
			return err
		}
		return run.clearTransactionFiles()
	}
	if txn.LocalCommit == "" {
		return fmt.Errorf("accepted reset transaction has no local commit")
	}

	head, exists, err := run.repo.HeadIfExists()
	if err != nil {
		return err
	}
	if txn.BaseCommit == "" {
		switch {
		case exists && head == txn.LocalCommit:
			if err := run.repo.ApplyCommit("", txn.LocalCommit); err != nil {
				return err
			}
		case !exists:
			if err := run.repo.ApplyCommit("", ""); err != nil {
				return err
			}
		default:
			return fmt.Errorf("metadata branch changed while resetting genesis")
		}
		txn.LocalAccepted = false
		if err := run.saveTransaction(txn); err != nil {
			return err
		}
		return run.clearTransactionFiles()
	}

	switch {
	case exists && head == txn.LocalCommit:
		if err := run.repo.ApplyCommit(txn.BaseCommit, txn.LocalCommit); err != nil {
			return err
		}
	case exists && head == txn.BaseCommit:
		if err := run.repo.ApplyCommit(txn.BaseCommit, txn.BaseCommit); err != nil {
			return err
		}
	case !exists:
		return fmt.Errorf("metadata branch disappeared while resetting revision")
	default:
		return fmt.Errorf("metadata branch changed while resetting revision")
	}
	txn.LocalAccepted = false
	if err := run.saveTransaction(txn); err != nil {
		return err
	}
	return run.clearTransactionFiles()
}
