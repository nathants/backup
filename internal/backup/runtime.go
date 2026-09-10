package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"backup/internal/durable"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
	"backup/internal/securefs"

	"github.com/nathants/go-libsodium"
	"github.com/nathants/go-libsodium/keysource"
	"golang.org/x/sys/unix"
)

type runtime struct {
	options                    Options
	config                     localconfig.Config
	repo                       *repository.Managed
	store                      *durable.Store
	lock                       *os.File
	clients                    map[string]*objectstore.Client
	candidateState             *repository.State
	capturedCandidateValidated bool
	preparation                *preparation
}

func openRuntime(options Options, requireRepository bool) (*runtime, error) {
	normalized, err := options.normalized()
	if err != nil {
		return nil, err
	}
	var preparation *preparation
	if requireRepository {
		preparation, err = readPreparation(normalized)
		if err != nil {
			return nil, err
		}
	}
	config := localconfig.Config{Branch: "main"}
	if preparation == nil || preparation.GitRemote != "" {
		config, err = localconfig.Load(normalized.ConfigPath)
		if err != nil {
			return nil, err
		}
	}
	if preparation != nil && preparation.GitRemote != "" && (preparation.GitRemote != config.GitRemote || preparation.Branch != config.Branch) {
		return nil, fmt.Errorf("first publication remote does not match its durable pin")
	}
	run := &runtime{options: normalized, config: config, preparation: preparation}
	if requireRepository {
		var repo *repository.Managed
		if preparation != nil {
			repo, err = repository.OpenLocal(normalized.repositoryPath(), config.Branch)
		} else {
			repo, err = repository.OpenManaged(normalized.repositoryPath(), config.GitRemote, config.Branch)
		}
		if err != nil {
			return nil, err
		}
		run.repo = repo
		run.repo.MaterializationFailurePoint = normalized.failurePoint
		run.repo.ValidationCache = filepath.Join(run.options.statePath(), validatedAncestorFile)
		if err := run.openStateAndLock(); err != nil {
			return nil, err
		}
		current, err := readPreparation(normalized)
		if err != nil || (current == nil) != (preparation == nil) || current != nil && *current != *preparation {
			_ = run.close()
			return nil, fmt.Errorf("local preparation changed while acquiring the lock; retry: %v", err)
		}
		if preparation != nil && preparation.GitRemote != "" {
			if err := run.repo.BindInitialRemote(config.GitRemote, config.Branch); err != nil {
				_ = run.close()
				return nil, err
			}
		}
	}
	return run, nil
}

func (run *runtime) openStateAndLock() error {
	if err := ensurePrivateDirectory(run.options.statePath()); err != nil {
		return fmt.Errorf("create operational state: %w", err)
	}
	lockPath := filepath.Join(run.options.statePath(), "lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open repository lock: %w", err)
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(fd, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		if err != nil {
			return fmt.Errorf("inspect repository lock: %w", err)
		}
		return fmt.Errorf("repository lock must be a regular file")
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("set repository-lock mode: %w", err)
	}
	run.lock = os.NewFile(uintptr(fd), lockPath)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = run.lock.Close()
		run.lock = nil
		return fmt.Errorf("backup repository is locked by another operation: %w", err)
	}
	store, err := durable.Open(run.options.statePath())
	if err != nil {
		_ = run.close()
		return err
	}
	run.store = store
	if err := run.repo.RecoverMaterialization(); err != nil {
		_ = run.close()
		return fmt.Errorf("recover metadata worktree materialization: %w", err)
	}
	return nil
}

func (run *runtime) close() error {
	var errs []error
	if run.store != nil {
		if err := run.store.Close(); err != nil {
			errs = append(errs, err)
		}
		run.store = nil
	}
	if run.lock != nil {
		if err := unix.Flock(int(run.lock.Fd()), unix.LOCK_UN); err != nil {
			errs = append(errs, err)
		}
		if err := run.lock.Close(); err != nil {
			errs = append(errs, err)
		}
		run.lock = nil
	}
	return errors.Join(errs...)
}

func (run *runtime) reportf(pattern string, values ...any) error {
	if _, err := fmt.Fprintf(run.options.Stderr, pattern, values...); err != nil {
		return fmt.Errorf("write diagnostic output: %w", err)
	}
	return nil
}

func (run *runtime) checkpoint(name string) error {
	if run.options.failurePoint == nil {
		return nil
	}
	if err := run.options.failurePoint(name); err != nil {
		return fmt.Errorf("failure at transaction checkpoint %s: %w", name, err)
	}
	return nil
}

func (run *runtime) loadTransaction() (*transaction, error) {
	var txn transaction
	if err := run.store.Read(transactionFilename, &txn); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if cleanupErr := removeTreeIfPresent(run.options.transactionFilesPath()); cleanupErr != nil {
				return nil, fmt.Errorf("clean unreferenced transaction files: %w", cleanupErr)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("read transaction state: %w", err)
	}
	if err := run.hydrateTransactionFiles(&txn); err != nil {
		return nil, fmt.Errorf("hydrate durable transaction files: %w", err)
	}
	var candidate *repository.State
	if len(txn.CandidateFiles) != 0 {
		state, err := run.loadCandidateState(&txn)
		if err != nil {
			return nil, fmt.Errorf("load file-backed candidate: %w", err)
		}
		candidate = &state
	}
	if err := run.validateTransaction(txn, candidate); err != nil {
		return nil, fmt.Errorf("invalid durable transaction: %w", err)
	}
	// Reset and post-completion cleanup no longer need staged bytes. Skipping
	// them here makes deletion of transaction-files safely replayable after a
	// crash while the durable transaction record still exists.
	if !txn.Resetting && !hasRevisionComplete(&txn) {
		if err := run.validateStagedTransaction(txn); err != nil {
			return nil, fmt.Errorf("invalid durable staging: %w", err)
		}
	}
	return &txn, nil
}

func (run *runtime) saveTransaction(txn *transaction) error {
	if txn == nil {
		return fmt.Errorf("nil transaction")
	}
	var candidate *repository.State
	if len(txn.CandidateFiles) != 0 {
		state, err := run.loadCandidateState(txn)
		if err != nil {
			return fmt.Errorf("load file-backed candidate: %w", err)
		}
		candidate = &state
	}
	if err := run.validateTransaction(*txn, candidate); err != nil {
		return err
	}
	return run.store.Write(transactionFilename, txn)
}

func (run *runtime) validateTransaction(txn transaction, candidate *repository.State) error {
	if txn.Version != stateVersion {
		return fmt.Errorf("unsupported state version %d", txn.Version)
	}
	if err := run.walkDataParts(&txn, nil); err != nil {
		return err
	}
	if txn.Kind != "initial" && txn.Kind != "genesis" && txn.Kind != "ordinary" && txn.Kind != "repair" {
		return fmt.Errorf("invalid transaction kind %q", txn.Kind)
	}
	if txn.Kind == "genesis" && (txn.Plan == nil || txn.Capture != nil) {
		return fmt.Errorf("genesis publication must retain the initial add plan")
	}
	if txn.Kind == "initial" && (txn.Plan == nil || txn.Capture != nil || len(txn.CandidateFiles) != 0) {
		return fmt.Errorf("initial preparation contains publication progress")
	}
	if txn.Kind == "initial" || txn.Kind == "genesis" {
		if txn.BaseCommit != "" {
			return fmt.Errorf("genesis transaction has a base commit")
		}
	} else if !isCommitID(txn.BaseCommit) {
		return fmt.Errorf("transaction has invalid base commit")
	}
	if txn.Plan != nil {
		if txn.Plan.Entries < 0 || txn.Plan.Entries == 0 && !txn.Plan.AllowEmpty || txn.Plan.IndexFile.RelativePath == "" {
			return fmt.Errorf("invalid or unexpectedly empty add plan")
		}
		if len(txn.Plan.ConfigFiles) != 3 {
			return fmt.Errorf("add plan does not contain exactly three configuration files")
		}
		for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
			if txn.Plan.ConfigFiles[name].RelativePath == "" {
				return fmt.Errorf("add plan lacks configuration %q", name)
			}
		}
	}
	if txn.Plan != nil && len(txn.CandidateFiles) == 0 {
		if txn.Kind != "ordinary" && txn.Kind != "initial" || txn.DataPartCount != 0 || txn.LocalCommit != "" || txn.LocalAccepted || txn.Metadata != nil || txn.PushAttempted || txn.PushConfirmed || len(txn.Mirrors) != 0 {
			return fmt.Errorf("add plan contains commit progress")
		}
		if txn.Capture != nil {
			if txn.Capture.NextPlan < 0 || txn.Capture.NextPlan > txn.Plan.Entries || txn.Capture.Mirrors == nil || txn.Capture.WarningSummary && txn.Capture.Warnings <= txn.Capture.WarningsShown {
				return fmt.Errorf("invalid capture progress cursor, warning summary, or mirror set")
			}
			for name, complete := range txn.Capture.Mirrors {
				if name == "" || !complete {
					return fmt.Errorf("invalid capture mirror progress")
				}
			}
		}
		return nil
	}
	if candidate == nil {
		return fmt.Errorf("transaction candidate does not contain exactly seven blobs")
	}
	state := *candidate
	if err := state.Validate(); err != nil {
		return err
	}
	if !equalHashes(txn.CandidateHashes, state.BlobHashes) {
		return fmt.Errorf("candidate blob hashes disagree with bytes")
	}
	if txn.Capture != nil {
		if txn.Kind != "ordinary" || txn.Plan == nil || txn.Capture.NextPlan != txn.Plan.Entries || len(txn.Capture.Mirrors) == 0 || txn.DataPartCount != 0 {
			return fmt.Errorf("captured ordinary transaction has inconsistent durable progress")
		}
	}
	if txn.Kind == "repair" && txn.DataPartCount == 0 || txn.Kind != "repair" && txn.DataPartCount != 0 {
		return fmt.Errorf("durable transaction has an invalid staged data-part count")
	}
	if txn.LocalCommit != "" && !isCommitID(txn.LocalCommit) {
		return fmt.Errorf("invalid local commit")
	}
	if txn.LocalAccepted && txn.LocalCommit == "" || txn.PushAttempted && !txn.LocalAccepted || txn.PushConfirmed && !txn.PushAttempted || txn.Metadata != nil && txn.LocalCommit == "" {
		return fmt.Errorf("transaction stages are inconsistent")
	}
	seenPaths := make(map[string]bool)
	if txn.Metadata != nil {
		if txn.Metadata.Manifest.TipCommit != txn.LocalCommit {
			return fmt.Errorf("metadata manifest tip disagrees with local commit")
		}
		if txn.Metadata.ManifestHash == "" || txn.Metadata.ManifestObjectID == "" || txn.Metadata.ManifestRelativePath == "" || txn.Metadata.PartsDirectory == "" || len(txn.Metadata.Manifest.Parts) == 0 {
			return fmt.Errorf("metadata staging is incomplete")
		}
		if err := validStagedRelativePath(txn.Metadata.ManifestRelativePath); err != nil {
			return fmt.Errorf("invalid staged manifest path: %w", err)
		}
		if err := validStagedRelativePath(txn.Metadata.PartsDirectory); err != nil {
			return fmt.Errorf("invalid staged metadata-parts directory: %w", err)
		}
		if _, err := format.MetadataManifestKey(txn.Metadata.Manifest.TipCommit, txn.Metadata.ManifestHash, txn.Metadata.ManifestObjectID); err != nil {
			return fmt.Errorf("invalid staged metadata manifest identity: %w", err)
		}
		for index := range txn.Metadata.Manifest.Parts {
			relative, err := metadataPartRelative(txn.Metadata, index)
			if err != nil {
				return err
			}
			if err := validStagedRelativePath(relative); err != nil {
				return fmt.Errorf("invalid staged metadata-part path: %w", err)
			}
			if seenPaths[relative] {
				return fmt.Errorf("durable transaction contains a duplicate staged path")
			}
			seenPaths[relative] = true
		}
		if seenPaths[txn.Metadata.ManifestRelativePath] {
			return fmt.Errorf("durable transaction contains a duplicate staged path")
		}
		seenPaths[txn.Metadata.ManifestRelativePath] = true
	}
	if err := run.validateDataPartCatalog(&txn, seenPaths, func(visit func(format.PackEntry) error) error {
		return state.WalkPacks(format.DefaultLimits(), visit)
	}, false); err != nil {
		return err
	}
	if err := validateTransactionProgress(txn, state); err != nil {
		return err
	}
	return nil
}

func validateTransactionProgress(txn transaction, state repository.State) error {
	canonicalMirrors := make(map[string]bool, len(state.Mirrors))
	for _, mirror := range state.Mirrors {
		canonicalMirrors[mirror.Name] = true
	}
	metadataCount := uint32(0)
	if txn.Metadata != nil {
		if len(txn.Metadata.Manifest.Parts) > int(^uint32(0)) {
			return fmt.Errorf("metadata part count is not representable")
		}
		metadataCount = uint32(len(txn.Metadata.Manifest.Parts))
	}
	for name, progress := range txn.Mirrors {
		if !canonicalMirrors[name] {
			return fmt.Errorf("durable transaction contains progress for unknown mirror %q", name)
		}
		if progress == nil || progress.DataPartCursor > txn.DataPartCount || progress.MetadataPartCursor > metadataCount {
			return fmt.Errorf("durable transaction contains invalid progress for mirror %q", name)
		}
		if progress.DataComplete {
			if txn.Capture != nil {
				if !txn.Capture.Mirrors[name] {
					return fmt.Errorf("mirror %s claims captured-data completion without completed-pack evidence", name)
				}
			} else if progress.DataPartCursor != txn.DataPartCount {
				return fmt.Errorf("mirror %s claims data completion before every staged data part", name)
			}
		}
		if progress.RevisionComplete && (txn.Metadata == nil || !txn.PushConfirmed) {
			return fmt.Errorf("mirror %s claims revision completion before metadata staging and confirmed publication", name)
		}
		if progress.MetadataPartCursor != 0 || progress.MetadataManifest {
			if txn.Metadata == nil || !txn.PushConfirmed {
				return fmt.Errorf("mirror %s claims metadata progress before metadata staging and confirmed publication", name)
			}
		}
		if progress.MetadataManifest && progress.MetadataPartCursor != metadataCount {
			return fmt.Errorf("mirror %s claims manifest completion without every metadata part", name)
		}
		if progress.RevisionComplete && (!progress.DataComplete || !progress.MetadataManifest) {
			return fmt.Errorf("mirror %s claims revision completion without complete data and metadata", name)
		}
	}
	return nil
}

func validStagedRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("invalid staged relative path %q", value)
	}
	for _, component := range strings.Split(value, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid staged path component")
		}
		for _, character := range []byte(component) {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.') {
				return fmt.Errorf("invalid staged path character")
			}
		}
	}
	return nil
}

func (run *runtime) stagedRelativePath(absolute string) (string, error) {
	relative, err := filepath.Rel(run.options.transactionFilesPath(), absolute)
	if err != nil || validStagedRelativePath(relative) != nil {
		return "", fmt.Errorf("staged file escaped transaction directory")
	}
	return relative, nil
}

func (run *runtime) openStaged(relative string) (*os.File, error) {
	if err := validStagedRelativePath(relative); err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(run.options.transactionFilesPath(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(rootFD) }()
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), relative)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("staged path %q must be a regular file", relative)
	}
	return file, nil
}

func (run *runtime) stagedPath(relative string) (string, error) {
	if err := validStagedRelativePath(relative); err != nil {
		return "", err
	}
	return filepath.Join(run.options.transactionFilesPath(), relative), nil
}

func (run *runtime) putStaged(ctx context.Context, writer *objectstore.Client, key, relative string, expected objectstore.Object) objectstore.CreateResult {
	file, err := run.openStaged(relative)
	if err != nil {
		return objectstore.CreateResult{Disposition: objectstore.CreateFailed, Err: err}
	}
	defer func() { _ = file.Close() }()
	return writer.PutOpenFile(ctx, key, file, expected)
}

func (run *runtime) readStaged(relative string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, fmt.Errorf("invalid staged read limit")
	}
	file, err := run.openStaged(relative)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader := io.Reader(file)
	if limit < int64(^uint64(0)>>1) {
		reader = io.LimitReader(file, limit+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("staged file exceeds %d bytes", limit)
	}
	return data, nil
}

func (run *runtime) validateStagedObject(relative string, expected objectstore.Object) error {
	file, err := run.openStaged(relative)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	actual, err := objectstore.HashReader(file)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("staged object identity changed")
	}
	return nil
}

func (run *runtime) validateStagedTransaction(txn transaction) error {
	if err := run.walkDataParts(&txn, func(_ uint64, part stagedDataPart) error {
		expected := objectstore.Object{Size: part.Entry.PartSize, BLAKE2b: part.Entry.PartHash, SHA256: part.Entry.PartSHA256, MD5: part.Entry.PartMD5}
		if err := run.validateStagedObject(part.RelativePath, expected); err != nil {
			return fmt.Errorf("data part %s: %w", part.RelativePath, err)
		}
		return nil
	}); err != nil {
		return err
	}
	if txn.Metadata == nil {
		return nil
	}
	for index, part := range txn.Metadata.Manifest.Parts {
		relative, err := metadataPartRelative(txn.Metadata, index)
		if err != nil {
			return err
		}
		expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
		if err := run.validateStagedObject(relative, expected); err != nil {
			return fmt.Errorf("metadata part %s: %w", relative, err)
		}
	}
	manifestBytes, err := run.readStaged(txn.Metadata.ManifestRelativePath, 1<<20)
	if err != nil {
		return err
	}
	expectedManifestBytes, err := txn.Metadata.Manifest.MarshalText()
	if err != nil {
		return err
	}
	if !bytes.Equal(manifestBytes, expectedManifestBytes) {
		return fmt.Errorf("staged metadata manifest bytes disagree with durable state")
	}
	if objectstore.HashBytes(manifestBytes).BLAKE2b != txn.Metadata.ManifestHash {
		return fmt.Errorf("staged metadata manifest identity changed")
	}
	return nil
}

func (run *runtime) loadLedger(repositoryUUID string) (completionLedger, error) {
	var ledger completionLedger
	if err := run.store.Read(ledgerFilename, &ledger); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newCompletionLedger(repositoryUUID), nil
		}
		return completionLedger{}, err
	}
	if ledger.Version != stateVersion || ledger.RepositoryUUID != repositoryUUID || ledger.Mirrors == nil || ledger.Quarantined == nil {
		return completionLedger{}, fmt.Errorf("completion ledger does not match repository identity")
	}
	if ledger.ForwardRepair != "" && !isCommitID(ledger.ForwardRepair) {
		return completionLedger{}, fmt.Errorf("invalid forward-repair anchor")
	}
	for name, quarantined := range ledger.Quarantined {
		if name == "" || !quarantined || ledger.Incident == 0 {
			return completionLedger{}, fmt.Errorf("invalid mirror quarantine")
		}
	}
	for name, commit := range ledger.Mirrors {
		if name == "" || !isCommitID(commit) || ledger.Quarantined[name] {
			return completionLedger{}, fmt.Errorf("completion ledger contains an invalid row")
		}
	}
	return ledger, nil
}

func (run *runtime) saveLedger(ledger completionLedger) error {
	return run.store.Write(ledgerFilename, &ledger)
}

func (run *runtime) clearTransactionFiles() error {
	run.candidateState = nil
	// Remove the control record first. After that durable boundary, leftover
	// private files are unreferenced and the next add/init can clean them. This
	// ordering prevents a crash from leaving a live transaction whose required
	// file-backed state has already disappeared.
	if err := os.Remove(filepath.Join(run.options.statePath(), transactionFilename)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDirectory(run.options.statePath()); err != nil {
		return err
	}
	if err := run.checkpoint("transaction-control-cleared"); err != nil {
		return err
	}
	path := run.options.transactionFilesPath()
	if err := removeTreeNoFollow(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(run.options.statePath())
}

func (run *runtime) prepareTransactionFiles() error {
	path := run.options.transactionFilesPath()
	if err := removeTreeNoFollow(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return ensurePrivateDirectory(path)
}

func (run *runtime) historyValidator() repository.Validator {
	return repository.Validator{
		Repo: run.repo.Directory, Limits: format.DefaultLimits(),
		CachePath: filepath.Join(run.options.statePath(), validatedAncestorFile),
	}
}

func (run *runtime) validatedHead(fetch bool) (repository.ValidatedCommit, *repository.History, error) {
	if run.preparation != nil && run.preparation.GitRemote == "" {
		return repository.ValidatedCommit{}, nil, fmt.Errorf("repository is local-only; run add and commit to publish the first backup")
	}
	if run.preparation != nil {
		// First publication never adopts an unrelated remote's history.
		fetch = false
	}
	if fetch {
		if err := run.repo.Fetch(); err != nil {
			return repository.ValidatedCommit{}, nil, fmt.Errorf("fetch metadata: %w", err)
		}
		remoteRevision := "refs/remotes/origin/" + run.config.Branch
		history, err := run.historyValidator().ValidateHistory(remoteRevision)
		if err != nil {
			return repository.ValidatedCommit{}, nil, err
		}
		remote, err := history.Tip()
		if err != nil {
			_ = history.Close()
			return repository.ValidatedCommit{}, nil, err
		}
		localHead, localErr := run.repo.Head()
		if localErr != nil {
			_ = history.Close()
			return repository.ValidatedCommit{}, nil, fmt.Errorf("resolve local metadata head: %w", localErr)
		}
		if localHead != remote.CommitID {
			_, found, findErr := history.IndexOf(localHead)
			if findErr != nil {
				_ = history.Close()
				return repository.ValidatedCommit{}, nil, findErr
			}
			if !found {
				_ = history.Close()
				return repository.ValidatedCommit{}, nil, fmt.Errorf("local metadata head %s is not an ancestor of validated remote head %s", localHead, remote.CommitID)
			}
			// Compare with the local base, not the fetched tree: a clean local
			// checkout can legitimately differ from the newer remote revision.
			status, err := run.repo.Status()
			if err != nil {
				_ = history.Close()
				return repository.ValidatedCommit{}, nil, fmt.Errorf("inspect local metadata before fast-forward: %w", err)
			}
			if !status.Clean {
				_ = history.Close()
				return repository.ValidatedCommit{}, nil, fmt.Errorf("cannot fast-forward metadata over local changes %q; save edits separately and restore a clean local worktree before retrying", status.Paths)
			}
			if err := run.repo.ApplyCommit(remote.CommitID, localHead); err != nil {
				_ = history.Close()
				return repository.ValidatedCommit{}, nil, err
			}
		}
		return remote, history, nil
	}
	head, err := run.repo.Head()
	if err != nil {
		return repository.ValidatedCommit{}, nil, err
	}
	history, err := run.historyValidator().ValidateHistory(head)
	if err != nil {
		return repository.ValidatedCommit{}, nil, err
	}
	tip, err := history.Tip()
	if err != nil {
		_ = history.Close()
		return repository.ValidatedCommit{}, nil, err
	}
	return tip, history, nil
}

func (run *runtime) requirePinnedMirrors(state repository.State) error {
	return run.config.RequireCanonicalMirrors(state.Mirrors)
}

func (run *runtime) client(ctx context.Context, mirror localconfig.Mirror) (*objectstore.Client, error) {
	if run.clients == nil {
		run.clients = make(map[string]*objectstore.Client)
	}
	if client := run.clients[mirror.Canonical.Name]; client != nil {
		return client, nil
	}
	var client *objectstore.Client
	var err error
	if run.options.ClientFactory != nil {
		client, err = run.options.ClientFactory(ctx, mirror)
	} else {
		if mirror.Profile == "-" {
			return nil, fmt.Errorf("mirror %s has no credential profile", mirror.Canonical.Name)
		}
		client, err = objectstore.New(ctx, objectstore.Options{Mirror: mirror.Canonical, Profile: mirror.Profile, CAFile: mirror.CAFile})
	}
	if err != nil {
		return nil, err
	}
	run.clients[mirror.Canonical.Name] = client
	return client, nil
}

func (run *runtime) mirror(name string) (localconfig.Mirror, bool) {
	for _, mirror := range run.config.Mirrors {
		if mirror.Canonical.Name == name {
			return mirror, true
		}
	}
	return localconfig.Mirror{}, false
}

func (run *runtime) secretKey(ctx context.Context) (*libsodium.Keyring, error) {
	libsodium.Init()
	return keysource.Load(ctx, run.config.GitRemote)
}

func equalHashes(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func randomHex(count int) (string, error) {
	data := make([]byte, count)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func randomUUID() (string, error) {
	var data [16]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", err
	}
	data[6] = data[6]&0x0f | 0x40
	data[8] = data[8]&0x3f | 0x80
	text := hex.EncodeToString(data[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:], nil
}

func isCommitID(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func atomicWritePrivate(path string, data []byte) error {
	return atomicWritePrivateFrom(path, bytes.NewReader(data))
}

func atomicWritePrivateFrom(path string, source io.Reader) error {
	if source == nil {
		return fmt.Errorf("private-file source is required")
	}
	return atomicWritePrivateGenerated(path, func(destination io.Writer) error {
		_, err := io.CopyBuffer(destination, source, make([]byte, 1<<20))
		return err
	})
}

func atomicWritePrivateGenerated(path string, generate func(io.Writer) error) error {
	if generate == nil {
		return fmt.Errorf("private-file generator is required")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".backup-state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	published := false
	defer func() {
		_ = file.Close()
		if !published {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := generate(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	published = true
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func removeTreeNoFollow(root string) error {
	return securefs.RemoveTree(root)
}

func sortedMirrorNames(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for name, value := range values {
		if value {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}
