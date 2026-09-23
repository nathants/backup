package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

const preparationFilename = "preparation.json"

// This record distinguishes an intentionally unborn local repository from a
// damaged established one. Absence never authorizes initialization or cleanup.
type preparation struct {
	Version    int    `json:"version"`
	FormatHash string `json:"format_hash"`
	GitRemote  string `json:"git_remote"`
	Branch     string `json:"branch"`
}

func readPreparation(options Options) (*preparation, error) {
	data, err := readRegularMode(filepath.Join(options.statePath(), preparationFilename), 64<<10, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p preparation
	if err := decodeOneJSON(data, &p); err != nil {
		return nil, err
	}
	if p.Version != 1 || len(p.FormatHash) != 128 || (p.GitRemote == "") != (p.Branch == "") {
		return nil, fmt.Errorf("invalid local preparation record")
	}
	return &p, nil
}

// Preparation has no committed base. Parse the same seven files and preserve
// every canonical content check, but require the uncommitted catalogs empty.
func (run *runtime) preparationBlobs() (map[string][]byte, repository.State, error) {
	entries, err := os.ReadDir(run.repo.Directory)
	if err != nil {
		return nil, repository.State{}, err
	}
	allowed := map[string]bool{".git": true, operationalStateDirName: true}
	for _, name := range repository.RequiredBlobNames {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return nil, repository.State{}, fmt.Errorf("unrelated metadata path %q", entry.Name())
		}
	}
	blobs := make(map[string][]byte, 7)
	for _, name := range repository.RequiredBlobNames {
		limit := configurationByteLimit(name)
		if name == "FORMAT" {
			limit = 64 << 10
		}
		catalog := name == "index.tsv" || name == "objects.tsv" || name == "packs.tsv"
		if catalog {
			limit = 1
		}
		path := filepath.Join(run.repo.Directory, name)
		data, err := readRegularNoFollow(path, limit)
		if err != nil {
			return nil, repository.State{}, fmt.Errorf("read initial metadata %q: %w", name, err)
		}
		if catalog && len(data) != 0 {
			return nil, repository.State{}, fmt.Errorf("initial catalog %q must be empty", name)
		}
		blobs[name] = data
	}
	if objectstore.HashBytes(blobs["FORMAT"]).BLAKE2b != run.preparation.FormatHash {
		return nil, repository.State{}, fmt.Errorf("initialized repository identity changed")
	}
	state, err := repository.ParsePreparationState(blobs, format.DefaultLimits())
	return blobs, state, err
}

func (run *runtime) addInitial(ctx context.Context, allowEmpty bool) (AddResult, error) {
	if err := ctx.Err(); err != nil {
		return AddResult{}, err
	}
	txn, err := run.loadTransaction()
	if err != nil {
		return AddResult{}, err
	}
	if txn != nil && txn.Kind != "initial" {
		return AddResult{}, fmt.Errorf("first commit is in progress; resume commit or reset before adding")
	}
	if _, exists, err := run.repo.HeadIfExists(); err != nil {
		return AddResult{}, err
	} else if exists {
		return AddResult{}, fmt.Errorf("local history exists during preparation; resume the first commit")
	}
	blobs, base, err := run.preparationBlobs()
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
	config := map[string][]byte{"ignore": blobs["ignore"], ".publickeys": blobs[".publickeys"], "mirrors.tsv": blobs["mirrors.tsv"]}
	scan, plan, unique, packs, _, err := run.buildAddPlan(root, base.Ignore, config, base, allowEmpty)
	if err != nil {
		return AddResult{}, err
	}
	next := newTransaction("initial", "", run.options.Now().UTC())
	next.Plan = plan
	if err := run.saveTransaction(&next); err != nil {
		return AddResult{}, err
	}
	if err := run.cleanupPlanGenerations(filepath.Dir(plan.IndexFile.RelativePath)); err != nil {
		return AddResult{}, err
	}
	if err := run.checkpoint("candidate-transaction-recorded"); err != nil {
		return AddResult{}, err
	}
	return AddResult{Entries: plan.Entries, UniqueNewObjects: unique, NewPacks: packs, Scan: scan}, nil
}

func (run *runtime) diffInitial(txn *transaction, visit func(Diff) error) (uint64, error) {
	// During genesis publication the worktree may be materializing. Its staged
	// genesis is the validated empty base; otherwise validate local preparation.
	var base repository.State
	var err error
	if txn.Kind == "genesis" {
		base, err = run.loadCandidateState(txn)
	} else {
		_, base, err = run.preparationBlobs()
	}
	if err != nil {
		return 0, err
	}
	if txn.Plan == nil {
		return 0, fmt.Errorf("first commit has no saved plan")
	}
	file, err := run.openStaged(txn.Plan.IndexFile.RelativePath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	return diffIndexReader(base, file, visit)
}

// startGenesis durably hands the initial path plan to the existing publication
// state machine. Only the previously absent mirror topology is filled from
// trusted configuration; ignore/recipients must still equal the add-time bytes.
func (run *runtime) startGenesis(txn *transaction) error {
	if txn == nil || txn.Kind != "initial" || txn.Plan == nil {
		return fmt.Errorf("run add before the first commit")
	}
	blobs, initial, err := run.preparationBlobs()
	if err != nil {
		return err
	}
	for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
		planned, err := run.readPlanConfig(txn, name)
		if err != nil {
			return err
		}
		if !bytes.Equal(planned, blobs[name]) {
			return fmt.Errorf("metadata configuration %q changed after add; run add again", name)
		}
	}
	if _, err := initial.PublicKeys.Latest(); err != nil {
		return err
	}
	config, err := localconfig.Load(run.options.ConfigPath)
	if err != nil {
		return err
	}
	if err := run.requirePlanOutsideFilesystemMirrors(txn.Plan, config); err != nil {
		return err
	}
	if err := repository.ValidateBranch(config.Branch); err != nil {
		return err
	}
	if run.preparation.GitRemote != "" && (run.preparation.GitRemote != config.GitRemote || run.preparation.Branch != config.Branch) {
		return fmt.Errorf("first publication remote does not match its durable pin")
	}
	mirrors := make([]format.Mirror, len(config.Mirrors))
	for i, m := range config.Mirrors {
		mirrors[i] = m.Canonical
	}
	mirrorBytes, err := format.MarshalMirrors(mirrors)
	if err != nil {
		return err
	}
	if len(blobs["mirrors.tsv"]) != 0 && !bytes.Equal(blobs["mirrors.tsv"], mirrorBytes) {
		return fmt.Errorf("initial mirrors do not match trusted configuration")
	}
	blobs["mirrors.tsv"] = mirrorBytes
	// Persist the authority before touching origin, so interrupted binding cannot
	// be resumed with a different destination or branch.
	run.preparation.GitRemote, run.preparation.Branch = config.GitRemote, config.Branch
	if err := run.store.Write(preparationFilename, run.preparation); err != nil {
		return err
	}
	if err := run.checkpoint("initial-remote-pinned"); err != nil {
		return err
	}
	if err := run.repo.BindInitialRemote(config.GitRemote, config.Branch); err != nil {
		return err
	}
	run.config = config
	next := newTransaction("genesis", "", run.options.Now().UTC())
	mirrorRef, err := run.ensureContentAddressedStagedBytes("candidate/initial-mirrors-", "", mirrorBytes, stagedFileRef{})
	if err != nil {
		return err
	}
	// Copy the map: the old persisted plan remains valid until saveTransaction.
	planCopy := *txn.Plan
	planCopy.ConfigFiles = make(map[string]stagedFileRef, 3)
	for k, v := range txn.Plan.ConfigFiles {
		planCopy.ConfigFiles[k] = v
	}
	planCopy.ConfigFiles["mirrors.tsv"] = mirrorRef
	next.Plan = &planCopy
	if err := run.stageCandidateBlobs(&next, blobs); err != nil {
		return err
	}
	if err := run.saveTransaction(&next); err != nil {
		return err
	}
	*txn = next
	return run.checkpoint("genesis-transaction-recorded")
}

func (run *runtime) finishPreparation() error {
	history, err := run.historyValidator().ValidateHistory("refs/heads/" + run.config.Branch)
	if err != nil {
		return err
	}
	tip, tipErr := history.Tip()
	_ = history.Close()
	if tipErr != nil {
		return tipErr
	}
	if tip.State.BlobHashes["FORMAT"] != run.preparation.FormatHash {
		return fmt.Errorf("published genesis disagrees with initialized repository identity")
	}
	if err := os.Remove(filepath.Join(run.options.statePath(), preparationFilename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(run.options.statePath()); err != nil {
		return err
	}
	run.preparation = nil
	return nil
}

func (run *runtime) commitInitial(ctx context.Context, txn *transaction) (*transaction, error) {
	if txn == nil {
		return nil, fmt.Errorf("run add before the first commit")
	}
	if txn.Kind == "initial" {
		if err := run.startGenesis(txn); err != nil {
			return nil, err
		}
	}
	if txn.Kind == "genesis" {
		candidate, err := run.loadCandidateState(txn)
		if err != nil {
			return nil, err
		}
		if candidate.BlobHashes["FORMAT"] != run.preparation.FormatHash {
			return nil, fmt.Errorf("staged genesis disagrees with initialized repository identity")
		}
		if _, err := run.commitTransaction(ctx, txn); err != nil {
			return nil, err
		}
		txn, err = run.loadTransaction()
		if err != nil {
			return nil, err
		}
	}
	if txn == nil || txn.Kind != "ordinary" || txn.Plan == nil {
		return nil, fmt.Errorf("initial publication lost its saved snapshot plan")
	}
	if err := run.finishPreparation(); err != nil {
		return nil, err
	}
	return txn, nil
}
