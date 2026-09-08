package backup

import (
	"fmt"
	"regexp"

	"backup/internal/format"
	"backup/internal/repository"
)

func Find(options Options, pattern, revision string, resolved func(string) error, visit func(format.IndexEntry) error) (uint64, error) {
	if pattern == "" {
		return 0, fmt.Errorf("regular expression is required")
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return 0, fmt.Errorf("invalid regular expression: %w", err)
	}
	run, err := openRuntime(options, true)
	if err != nil {
		return 0, err
	}
	defer func() { _ = run.close() }()
	if txn, err := run.loadTransaction(); err != nil {
		return 0, err
	} else if txn != nil && txn.PushAttempted {
		return 0, fmt.Errorf("a published transaction requires commit finalization before reading history")
	}
	head, history, err := run.validatedHead(true)
	if err != nil {
		return 0, err
	}
	defer func() { _ = history.Close() }()
	if err := run.requirePinnedMirrors(head.State); err != nil {
		return 0, err
	}
	commit, err := resolveHistoryRevision(run.repo, history, revision)
	if err != nil {
		return 0, err
	}
	if resolved != nil {
		if err := resolved(commit.CommitID); err != nil {
			return 0, err
		}
	}
	var count uint64
	if err := commit.State.WalkIndex(format.DefaultLimits(), func(entry format.IndexEntry) error {
		if !expression.MatchString(entry.Path) {
			return nil
		}
		if count == ^uint64(0) {
			return fmt.Errorf("find result count overflows")
		}
		count++
		if visit != nil {
			return visit(entry)
		}
		return nil
	}); err != nil {
		return count, err
	}
	return count, nil
}

func resolveHistoryRevision(repo *repository.Managed, history *repository.History, revision string) (repository.ValidatedCommit, error) {
	if history == nil || history.Len() == 0 {
		return repository.ValidatedCommit{}, fmt.Errorf("metadata history is empty")
	}
	if revision == "" || revision == "HEAD" {
		return history.Tip()
	}
	resolvedHistory, err := (repository.Validator{Repo: repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(revision)
	if err != nil {
		return repository.ValidatedCommit{}, err
	}
	defer func() { _ = resolvedHistory.Close() }()
	resolved, err := resolvedHistory.Tip()
	if err != nil {
		return repository.ValidatedCommit{}, err
	}
	_, found, err := history.IndexOf(resolved.CommitID)
	if err != nil {
		return repository.ValidatedCommit{}, err
	}
	if found {
		return resolved, nil
	}
	return repository.ValidatedCommit{}, fmt.Errorf("revision %s is not in the validated primary history", resolved.CommitID)
}
