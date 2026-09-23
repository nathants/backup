package backup

import (
	"context"
	"fmt"
	"sort"

	"backup/internal/format"
	"github.com/nathants/go-libsodium"
)

func Verify(ctx context.Context, options Options, minimumMirrors int, revision string) (VerifyResult, error) {
	defer startProgress(&options, "verify")()
	result := VerifyResult{Minimum: minimumMirrors}
	if minimumMirrors < 1 {
		return result, fmt.Errorf("minimum mirrors must be at least 1")
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
	selected, err := history.ResolveRevision(revision)
	if err != nil {
		return result, err
	}
	result.CommitID = selected.CommitID
	var secret *libsodium.Keyring
	if options.FullVerify {
		for _, mirror := range run.config.Mirrors {
			if mirror.Canonical.Kind != format.MirrorFilesystem {
				continue
			}
			secret, err = run.secretKey(ctx)
			if err != nil {
				return result, err
			}
			break
		}
	}
	// Restart the audit after new negative evidence, so every reinstated mirror
	// was checked AFTER the incident, regardless of mirror ordering. Each restart
	// quarantines a previously unquarantined mirror; the loop is bounded.
	for attempt := 0; attempt <= len(run.config.Mirrors); attempt++ {
		before, err := run.loadLedger(head.State.Format.RepositoryUUID)
		if err != nil {
			return result, err
		}
		result.Mirrors = nil
		result.Passed = 0
		for _, mirror := range run.config.Mirrors {
			verification := MirrorVerification{Name: mirror.Canonical.Name}
			auditErr := run.auditMirror(ctx, mirror, history, selected, txn)
			if auditErr == nil && options.FullVerify {
				auditErr = run.verifyFull(ctx, mirror, selected, txn, secret)
			}
			if err := auditErr; err != nil {
				if isIncidentStateError(err) {
					return result, err
				}
				verification.Error = terminalEscape(err.Error())
			} else {
				verification.Complete = true
				result.Passed++
			}
			run.options.progress.eventf("mirror=%s passed=%t detail=%s", mirror.Canonical.Name, verification.Complete, verification.Error)
			result.Mirrors = append(result.Mirrors, verification)
		}
		after, err := run.loadLedger(head.State.Format.RepositoryUUID)
		if err != nil {
			return result, err
		}
		if after.Incident != before.Incident {
			continue
		}
		if selected.CommitID == head.CommitID {
			for _, mirror := range result.Mirrors {
				if mirror.Complete {
					if err := run.recordVerified(head.State.Format.RepositoryUUID, mirror.Name, selected.CommitID); err != nil {
						return result, err
					}
				}
			}
		}
		sort.Slice(result.Mirrors, func(i, j int) bool { return result.Mirrors[i].Name < result.Mirrors[j].Name })
		if result.Passed < minimumMirrors {
			return result, fmt.Errorf("%d mirrors passed verification, fewer than required minimum %d", result.Passed, minimumMirrors)
		}
		return result, nil
	}
	return result, fmt.Errorf("mirror integrity changed throughout verification; retry")
}
