package backup

import (
	"fmt"
	"regexp"

	"backup/internal/format"
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
	txn, err := run.loadTransaction()
	if err != nil {
		return 0, err
	}
	head, history, err := run.validatedHead(txn == nil || !txn.LocalAccepted)
	if err != nil {
		return 0, err
	}
	defer func() { _ = history.Close() }()
	if err := run.requirePinnedMirrors(head.State); err != nil {
		return 0, err
	}
	commit, err := history.ResolveRevision(revision)
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
