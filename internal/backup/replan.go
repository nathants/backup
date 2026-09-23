package backup

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/repository"
)

// Replan refreshes path selection without refreshing known regular-file
// observations. It stays on the saved base and performs no remote operations.
// Add is the explicit way to discard these observations and hash everything.
func Replan(ctx context.Context, options Options) (AddResult, error) {
	if err := ctx.Err(); err != nil {
		return AddResult{}, err
	}
	run, err := openRuntime(options, true)
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil {
		return AddResult{}, err
	}
	if txn == nil || txn.Plan == nil {
		return AddResult{}, fmt.Errorf("replan requires an existing add plan; run add first")
	}
	if txn.Kind != "initial" && txn.Kind != "ordinary" || txn.Capture != nil || len(txn.CandidateFiles) != 0 || txn.DataPartCount != 0 || txn.LocalCommit != "" || txn.PushAttempted || txn.Resetting {
		return AddResult{}, fmt.Errorf("commit or reset progress already exists; finish it before replanning")
	}
	if err := run.cleanupPlanGenerations(txn.Plan); err != nil {
		return AddResult{}, err
	}
	if txn.Plan.ObservationsFile != nil {
		if err := run.validateStagedRef(*txn.Plan.ObservationsFile); err != nil {
			return AddResult{}, fmt.Errorf("validate staged observations: %w; run add to refresh observations", err)
		}
	}
	base, closeBase, err := run.replanBase(txn)
	if err != nil {
		return AddResult{}, err
	}
	defer closeBase()
	config := make(map[string][]byte, 3)
	for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
		data, err := readRegularNoFollow(filepath.Join(run.repo.Directory, name), configurationByteLimit(name))
		if err != nil {
			return AddResult{}, err
		}
		if name != "ignore" {
			previous, err := run.readPlanConfig(txn, name)
			if err != nil {
				return AddResult{}, err
			}
			if !bytes.Equal(previous, data) {
				return AddResult{}, fmt.Errorf("metadata configuration %q changed after add; run add to refresh it", name)
			}
		}
		config[name] = data
	}
	ignore, err := format.ParseIgnore(bytes.NewReader(config["ignore"]), configurationLimits("ignore"))
	if err != nil {
		return AddResult{}, err
	}
	root, err := filesystem.OpenRoot(run.options.Root)
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = root.Close() }()
	if err := run.cleanupAddBuilds(); err != nil {
		return AddResult{}, err
	}
	scan, plan, unique, packs, noChanges, err := run.buildAddPlan(ctx, root, ignore, config, base, txn.Plan.AllowEmpty, txn.Plan)
	if err != nil {
		return AddResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return AddResult{}, err
	}
	if err := run.checkpoint("replan-built"); err != nil {
		return AddResult{}, err
	}
	txn.Plan = plan
	if err := run.saveTransaction(txn); err != nil {
		return AddResult{}, err
	}
	if err := run.checkpoint("replan-recorded"); err != nil {
		return AddResult{}, err
	}
	if err := run.cleanupPlanGenerations(plan); err != nil {
		return AddResult{}, err
	}
	return AddResult{BaseCommit: txn.BaseCommit, Entries: plan.Entries, UniqueNewObjects: unique, NewPacks: packs, NoChanges: noChanges, Scan: scan}, nil
}

func (run *runtime) replanBase(txn *transaction) (repository.State, func(), error) {
	noop := func() {}
	if run.preparation != nil {
		if txn.Kind != "initial" {
			return repository.State{}, noop, fmt.Errorf("first publication has started; resume commit or reset")
		}
		if _, exists, err := run.repo.HeadIfExists(); err != nil {
			return repository.State{}, noop, err
		} else if exists {
			return repository.State{}, noop, fmt.Errorf("local history exists during preparation; resume the first commit")
		}
		_, base, err := run.preparationBlobs()
		return base, noop, err
	}
	head, err := run.repo.Head()
	if err != nil {
		return repository.State{}, noop, err
	}
	if head != txn.BaseCommit {
		return repository.State{}, noop, fmt.Errorf("metadata HEAD changed since add; run add to refresh the base")
	}
	history, err := run.historyValidator().ValidateHistory(txn.BaseCommit)
	if err != nil {
		return repository.State{}, noop, err
	}
	closeHistory := func() { _ = history.Close() }
	tip, err := history.Tip()
	if err != nil {
		closeHistory()
		return repository.State{}, noop, err
	}
	status, err := run.repo.StatusAgainst(tip.State)
	if err == nil {
		for _, path := range status.Paths {
			if path != "ignore" && path != ".publickeys" && path != "mirrors.tsv" {
				err = fmt.Errorf("metadata worktree contains unrelated change %q", path)
				break
			}
		}
	}
	if err != nil {
		closeHistory()
		return repository.State{}, noop, err
	}
	return tip.State, closeHistory, nil
}

func (run *runtime) stageObservations(ctx context.Context, prior, current *stagedPlan, workspace string) error {
	ref := prior.IndexFile
	if prior.ObservationsFile != nil {
		ref = *prior.ObservationsFile
	}
	old, err := run.openStaged(ref.RelativePath)
	if err != nil {
		return err
	}
	defer func() { _ = old.Close() }()
	next, err := run.openStaged(current.IndexFile.RelativePath)
	if err != nil {
		return err
	}
	defer func() { _ = next.Close() }()
	path := filepath.Join(workspace, "observations.tsv")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	writer := bufio.NewWriterSize(file, 256<<10)
	if err := mergeObservations(ctx, old, next, writer); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	relative := filepath.Join(filepath.Dir(current.IndexFile.RelativePath), "observations.tsv")
	destination, err := run.stagedPath(relative)
	if err != nil {
		return err
	}
	if err := atomicWritePrivateFrom(destination, file); err != nil {
		return err
	}
	identity, err := run.referenceStagedFile(relative)
	if err != nil {
		return err
	}
	current.ObservationsFile = &identity
	return nil
}
