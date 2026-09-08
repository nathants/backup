package backup

import (
	"context"
	"fmt"
	"sort"

	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func Verify(ctx context.Context, options Options, minimumMirrors int, revision string) (VerifyResult, error) {
	result := VerifyResult{Minimum: minimumMirrors}
	if minimumMirrors < 1 {
		return result, fmt.Errorf("minimum mirrors must be at least 1")
	}
	run, err := openRuntime(options, true)
	if err != nil {
		return result, err
	}
	defer run.close()
	if txn, err := run.loadTransaction(); err != nil {
		return result, err
	} else if txn != nil && txn.PushAttempted {
		return result, fmt.Errorf("a published transaction requires commit finalization before verification")
	}
	head, history, err := run.validatedHead(true)
	if err != nil {
		return result, err
	}
	defer history.Close()
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
	for _, mirror := range run.config.Mirrors {
		verification := MirrorVerification{Name: mirror.Canonical.Name}
		client, err := run.reader(ctx, mirror)
		if err == nil {
			err = auditManifestChain(ctx, client, history, targetIndex, selected.State.Format.RepositoryUUID, nil)
		}
		if err == nil {
			err = auditDataCatalog(ctx, client, selected.State)
		}
		if err != nil {
			verification.Error = terminalEscape(err.Error())
		} else {
			verification.Complete = true
			result.Passed++
		}
		result.Mirrors = append(result.Mirrors, verification)
	}
	sort.Slice(result.Mirrors, func(left, right int) bool { return result.Mirrors[left].Name < result.Mirrors[right].Name })
	if result.Passed < minimumMirrors {
		return result, fmt.Errorf("%d mirrors passed verification, fewer than required minimum %d", result.Passed, minimumMirrors)
	}
	return result, nil
}

func auditDataCatalog(ctx context.Context, client *objectstore.Client, state repository.State) error {
	return state.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		key, err := format.ObjectKey(part.PartHash, part.ObjectID)
		if err != nil {
			return err
		}
		expected := objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5}
		if err := client.Audit(ctx, key, expected); err != nil {
			return fmt.Errorf("data part %s: %w", key, err)
		}
		return nil
	})
}
