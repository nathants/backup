package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"backup/internal/extsort"
	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/pack"
	"backup/internal/repository"

	"github.com/nathants/go-libsodium"
	"golang.org/x/sys/unix"
)

func Add(ctx context.Context, options Options, allowEmpty bool) (AddResult, error) {
	defer startProgress(&options, "add")()
	if err := ctx.Err(); err != nil {
		return AddResult{}, err
	}
	run, err := openRuntime(options, true)
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = run.close() }()
	if run.preparation != nil {
		return run.addInitial(ctx, allowEmpty)
	}
	if err := run.cleanupAddBuilds(); err != nil {
		return AddResult{}, fmt.Errorf("clean stale add workspace: %w", err)
	}
	if txn, err := run.loadTransaction(); err != nil {
		return AddResult{}, err
	} else if txn != nil && (txn.Plan == nil || txn.Capture != nil || len(txn.CandidateFiles) != 0 || txn.DataPartCount != 0 || txn.LocalCommit != "" || txn.PushAttempted) {
		return AddResult{}, fmt.Errorf("commit progress already exists; finish commit or reset before replacing the add plan")
	} else if txn != nil {
		if err := run.cleanupPlanGenerations(txn.Plan); err != nil {
			return AddResult{}, err
		}
	}
	head, history, err := run.validatedHead(true)
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = history.Close() }()
	status, err := run.repo.StatusAgainst(head.State)
	if err != nil {
		return AddResult{}, err
	}
	for _, path := range status.Paths {
		if path != "ignore" && path != ".publickeys" && path != "mirrors.tsv" {
			return AddResult{}, fmt.Errorf("metadata worktree contains unrelated change %q", path)
		}
	}
	configBlobs := make(map[string][]byte, 3)
	for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
		data, err := readRegularNoFollow(filepath.Join(run.repo.Directory, name), configurationByteLimit(name))
		if err != nil {
			return AddResult{}, fmt.Errorf("read metadata configuration %q: %w", name, err)
		}
		configBlobs[name] = data
	}
	ignore, err := format.ParseIgnore(bytes.NewReader(configBlobs["ignore"]), configurationLimits("ignore"))
	if err != nil {
		return AddResult{}, err
	}
	publicKeys, err := libsodium.ParseKeyChains(bytes.NewReader(configBlobs[".publickeys"]))
	if err != nil {
		return AddResult{}, err
	}
	if err := libsodium.ValidateKeyChainTransition(head.State.PublicKeys, publicKeys); err != nil {
		return AddResult{}, err
	}
	mirrors, err := format.ParseMirrors(bytes.NewReader(configBlobs["mirrors.tsv"]), configurationLimits("mirrors.tsv"))
	if err != nil {
		return AddResult{}, err
	}
	if err := run.config.RequireCanonicalMirrors(mirrors); err != nil {
		return AddResult{}, err
	}
	if err := history.ValidateMirrorTopology(mirrors); err != nil {
		return AddResult{}, err
	}
	root, err := filesystem.OpenRoot(run.options.Root)
	if err != nil {
		return AddResult{}, err
	}
	defer func() { _ = root.Close() }()
	scan, plan, uniqueNew, newPacks, noChanges, err := run.buildAddPlan(ctx, root, ignore, configBlobs, head.State, allowEmpty, nil)
	if err != nil {
		return AddResult{}, err
	}
	txn := transaction{
		Version: stateVersion, Kind: "ordinary", BaseCommit: head.CommitID, Plan: plan,
		Mirrors: make(map[string]*mirrorProgress), CreatedUnixNano: run.options.Now().UTC().UnixNano(),
	}
	if err := run.saveTransaction(&txn); err != nil {
		return AddResult{}, err
	}
	if err := run.cleanupPlanGenerations(plan); err != nil {
		return AddResult{}, fmt.Errorf("clean superseded add plans: %w", err)
	}
	if err := run.checkpoint("candidate-transaction-recorded"); err != nil {
		return AddResult{}, err
	}
	return AddResult{BaseCommit: head.CommitID, Entries: plan.Entries, UniqueNewObjects: uniqueNew, NewPacks: newPacks, NoChanges: noChanges, Scan: scan}, nil
}

func (run *runtime) buildAddPlan(ctx context.Context, root *filesystem.Root, ignore format.Ignore, configBlobs map[string][]byte, base repository.State, allowEmpty bool, prior *stagedPlan) (filesystem.Result, *stagedPlan, int, int, bool, error) {
	ignore, err := run.filesystemScanIgnore(ignore)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	buildDirectory, err := os.MkdirTemp(run.options.statePath(), ".add-build-")
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	if err := os.Chmod(buildDirectory, 0o700); err != nil {
		_ = removeTreeIfPresent(buildDirectory)
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	buildRemoved := false
	defer func() {
		if !buildRemoved {
			_ = removeTreeIfPresent(buildDirectory)
		}
	}()

	var reuse func(string) (*format.IndexEntry, error)
	if prior != nil {
		ref := prior.IndexFile
		if prior.ObservationsFile != nil {
			ref = *prior.ObservationsFile
		}
		rows, err := run.openStaged(ref.RelativePath)
		if err != nil {
			return filesystem.Result{}, nil, 0, 0, false, err
		}
		defer func() { _ = rows.Close() }()
		index, err := newObservationIndex(ctx, filepath.Join(buildDirectory, "observations.index"), rows)
		if err != nil {
			return filesystem.Result{}, nil, 0, 0, false, err
		}
		defer func() { _ = index.file.Close() }()
		reuse = func(path string) (*format.IndexEntry, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return index.lookup(path)
		}
	}

	rawIndexPath := filepath.Join(buildDirectory, "index.raw")
	rawHashesPath := filepath.Join(buildDirectory, "hashes.raw")
	rawIndex, err := os.OpenFile(rawIndexPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	rawHashes, err := os.OpenFile(rawHashesPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = rawIndex.Close()
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	indexWriter := bufio.NewWriterSize(rawIndex, 256<<10)
	hashWriter := bufio.NewWriterSize(rawHashes, 256<<10)
	run.options.progress.phasef("scanning source and building path plan")
	var selected uint64
	var reportErr error
	scan, walkErr := root.WalkReusing(ignore, func(event filesystem.Event) {
		if reportErr == nil {
			if event.Detail != "" {
				reportErr = run.reportf("%s\t%s\t%s\n", event.Kind, terminalEscape(event.Path), terminalEscape(event.Detail))
			} else {
				reportErr = run.reportf("%s\t%s\n", event.Kind, terminalEscape(event.Path))
			}
		}
	}, reuse, func(file *filesystem.File, entry format.IndexEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reportErr != nil {
			return reportErr
		}
		selected++
		run.options.progress.detailf("selected paths=%d", selected)
		row, err := format.MarshalIndexEntry(entry)
		if err != nil {
			return err
		}
		if _, err := indexWriter.Write(row); err != nil {
			return err
		}
		if file != nil {
			if _, err := fmt.Fprintf(hashWriter, "%s\t%d\n", file.Hash, file.Size); err != nil {
				return err
			}
		}
		return nil
	})
	closeBuildFile := func(writer *bufio.Writer, file *os.File) error {
		return errors.Join(writer.Flush(), file.Sync(), file.Close())
	}
	indexCloseErr := closeBuildFile(indexWriter, rawIndex)
	hashCloseErr := closeBuildFile(hashWriter, rawHashes)
	if walkErr != nil || reportErr != nil || indexCloseErr != nil || hashCloseErr != nil {
		return filesystem.Result{}, nil, 0, 0, false, errors.Join(walkErr, reportErr, indexCloseErr, hashCloseErr)
	}
	if scan.Entries > uint64(^uint(0)>>1) {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("scan entry count is not representable")
	}
	entries := int(scan.Entries)
	if entries == 0 && !allowEmpty {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("scan produced an empty snapshot plan; use --allow-empty to accept it")
	}

	run.options.progress.detailf("selected paths=%d hashed files=%d reused files=%d", scan.Entries, scan.HashedFiles, scan.ReusedFiles)
	run.options.progress.phasef("sorting and validating path plan")
	firstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("generated row lacks a first field")
		}
		return field, nil
	}
	sortedIndexPath := filepath.Join(buildDirectory, "index.tsv")
	if err := extsort.SortFiles(buildDirectory, []string{rawIndexPath}, sortedIndexPath, extsort.Options{Unique: true, Key: firstField}); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("sort add plan: %w", err)
	}
	sortedHashesPath := filepath.Join(buildDirectory, "hashes.tsv")
	if err := extsort.SortFiles(buildDirectory, []string{rawHashesPath}, sortedHashesPath, extsort.Options{Key: firstField}); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("sort provisional content hashes: %w", err)
	}

	if ^uint64(0)-base.ObjectCount < scan.Entries {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("deduplication entry count overflow")
	}
	dedup, err := newDedupIndex(filepath.Join(buildDirectory, "dedup.index"), base.ObjectCount+scan.Entries)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	defer func() { _ = dedup.Close() }()
	if err := base.WalkObjects(format.DefaultLimits(), func(object format.ObjectEntry) error {
		return dedup.Insert(object.PlaintextHash, object.PlaintextSize)
	}); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	uniqueNew, newPacks, err := countProvisionalObjects(sortedHashesPath, dedup, run.options.PackTarget)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}

	if err := ensurePrivateDirectory(run.options.transactionFilesPath()); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	generation, err := randomHex(8)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	prefix := filepath.Join("plans", generation)
	generationPath, err := run.stagedPath(prefix)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(generationPath)); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	if err := ensurePrivateDirectory(generationPath); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	plan := &stagedPlan{Entries: entries, AllowEmpty: allowEmpty, ConfigFiles: make(map[string]stagedFileRef, 3)}
	indexSource, err := os.Open(sortedIndexPath)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	indexRelative := filepath.Join(prefix, "index.tsv")
	indexDestination, _ := run.stagedPath(indexRelative)
	copyErr := atomicWritePrivateFrom(indexDestination, indexSource)
	closeErr := indexSource.Close()
	if copyErr != nil || closeErr != nil {
		return filesystem.Result{}, nil, 0, 0, false, errors.Join(copyErr, closeErr)
	}
	plan.IndexFile, err = run.referenceStagedFile(indexRelative)
	if err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
		relative := filepath.Join(prefix, stagedMetadataName(name))
		ref, err := run.ensureStagedBytes(relative, configBlobs[name], stagedFileRef{})
		if err != nil {
			return filesystem.Result{}, nil, 0, 0, false, err
		}
		plan.ConfigFiles[name] = ref
	}
	if prior != nil {
		if err := run.stageObservations(ctx, prior, plan, buildDirectory); err != nil {
			return filesystem.Result{}, nil, 0, 0, false, err
		}
	}
	noChanges := plan.IndexFile.Size == base.BlobSizes["index.tsv"] && plan.IndexFile.BLAKE2b == base.BlobHashes["index.tsv"]
	for name, data := range configBlobs {
		identity := objectstore.HashBytes(data)
		noChanges = noChanges && identity.Size == base.BlobSizes[name] && identity.BLAKE2b == base.BlobHashes[name]
	}
	if err := dedup.Close(); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, err
	}
	if err := removeTreeIfPresent(buildDirectory); err != nil {
		return filesystem.Result{}, nil, 0, 0, false, fmt.Errorf("clean add-plan build workspace: %w", err)
	}
	buildRemoved = true
	return scan, plan, uniqueNew, newPacks, noChanges, nil
}

func (run *runtime) cleanupAddBuilds() error {
	fd, err := unix.Open(run.options.statePath(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), run.options.statePath())
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".add-build-") {
			continue
		}
		if err := removeTreeNoFollow(filepath.Join(run.options.statePath(), entry.Name())); err != nil {
			return err
		}
	}
	return syncDirectory(run.options.statePath())
}

// cleanupPlanGenerations runs under the repository lock, using a plan loaded
// from the authoritative transaction or one whose save completed successfully.
// Never call it with an unconfirmed replacement after a save error: the rename
// may have succeeded even though its final directory barrier failed.
func (run *runtime) cleanupPlanGenerations(plan *stagedPlan) error {
	keep := make(map[string]bool)
	protect := func(ref stagedFileRef) {
		parts := strings.SplitN(ref.RelativePath, string(filepath.Separator), 3)
		if len(parts) >= 2 && parts[0] == "plans" {
			keep[filepath.Join(parts[0], parts[1])] = true
		}
	}
	if plan != nil {
		protect(plan.IndexFile)
		for _, ref := range plan.ConfigFiles {
			protect(ref)
		}
		if plan.ObservationsFile != nil {
			protect(*plan.ObservationsFile)
		}
	}
	plansPath, err := run.stagedPath("plans")
	if err != nil {
		return err
	}
	fd, err := unix.Open(plansPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), plansPath)
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		relative := filepath.Join("plans", entry.Name())
		if keep[relative] {
			continue
		}
		path, err := run.stagedPath(relative)
		if err != nil {
			return err
		}
		if err := removeTreeNoFollow(path); err != nil {
			return err
		}
	}
	return syncDirectory(plansPath)
}

func countProvisionalObjects(path string, dedup *dedupIndex, target uint64) (int, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 512), 1024)
	unique, packs := 0, 0
	var packSize uint64
	packMembers := 0
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 2 {
			return 0, 0, fmt.Errorf("invalid generated provisional hash row")
		}
		size, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(size, 10) != fields[1] {
			return 0, 0, fmt.Errorf("invalid generated provisional size")
		}
		exists, err := dedup.Contains(fields[0], size)
		if err != nil {
			return 0, 0, err
		}
		if exists {
			continue
		}
		if err := dedup.Insert(fields[0], size); err != nil {
			return 0, 0, err
		}
		unique++
		wouldExceed := size > target || packSize > target-size || packMembers >= pack.MaximumMembersPerPack
		if packMembers == 0 || wouldExceed {
			packs++
			packSize, packMembers = 0, 0
		}
		if ^uint64(0)-packSize < size {
			packSize = ^uint64(0)
		} else {
			packSize += size
		}
		packMembers++
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return unique, packs, nil
}

func configurationByteLimit(name string) int64 {
	switch name {
	case "ignore":
		return format.MaximumIgnoreBytes
	case ".publickeys":
		return format.MaximumPublicKeysBytes
	case "mirrors.tsv":
		return format.MaximumMirrorsBytes
	default:
		return 0
	}
}

func configurationLimits(name string) format.Limits {
	limits := format.DefaultLimits()
	limits.MaxFileBytes = configurationByteLimit(name)
	return limits
}

func readRegularNoFollow(path string, maximum int64) ([]byte, error) {
	return readRegularMode(path, maximum, 0o644)
}

func readRegularMode(path string, maximum int64, mode os.FileMode) ([]byte, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("invalid regular-file byte limit")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("file must be a regular mode-%04o blob of at most %d bytes", mode, maximum)
	}
	reader := io.LimitReader(file, info.Size()+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("file size changed while reading")
	}
	return data, nil
}

func terminalEscape(value string) string {
	var output bytes.Buffer
	for _, char := range []byte(value) {
		if char >= 0x20 && char != 0x7f {
			output.WriteByte(char)
		} else {
			fmt.Fprintf(&output, "\\x%02x", char)
		}
	}
	return output.String()
}

func DiffCandidate(options Options, visit func(Diff) error) (uint64, error) {
	run, err := openRuntime(options, true)
	if err != nil {
		return 0, err
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil || txn == nil {
		return 0, err
	}
	if run.preparation != nil && (txn.Kind == "initial" || txn.Kind == "genesis") {
		return run.diffInitial(txn, visit)
	}
	validator := run.historyValidator()
	validator.CacheReadOnly = true
	history, err := validator.ValidateHistory(txn.BaseCommit)
	if err != nil {
		return 0, err
	}
	defer func() { _ = history.Close() }()
	tip, err := history.Tip()
	if err != nil {
		return 0, err
	}
	var indexFile *os.File
	if txn.Plan != nil && len(txn.CandidateFiles) == 0 {
		indexFile, err = run.openStaged(txn.Plan.IndexFile.RelativePath)
	} else {
		ref, ok := txn.CandidateFiles["index.tsv"]
		if !ok {
			return 0, fmt.Errorf("transaction has no candidate index")
		}
		indexFile, err = run.openStaged(ref.RelativePath)
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = indexFile.Close() }()
	return diffIndexReader(tip.State, indexFile, visit)
}

type streamedIndex struct {
	entries <-chan format.IndexEntry
	done    <-chan error
}

func startIndexStream(walk func(func(format.IndexEntry) error) error) streamedIndex {
	entries := make(chan format.IndexEntry, 1)
	done := make(chan error, 1)
	go func() {
		err := walk(func(entry format.IndexEntry) error {
			entries <- entry
			return nil
		})
		close(entries)
		done <- err
		close(done)
	}()
	return streamedIndex{entries: entries, done: done}
}

func diffIndexReader(oldState repository.State, reader io.Reader, visit func(Diff) error) (uint64, error) {
	oldStream := startIndexStream(func(emit func(format.IndexEntry) error) error {
		return oldState.WalkIndex(format.DefaultLimits(), emit)
	})
	newStream := startIndexStream(func(emit func(format.IndexEntry) error) error {
		return format.WalkIndex(reader, format.DefaultLimits(), emit)
	})
	oldEntry, oldOK := <-oldStream.entries
	newEntry, newOK := <-newStream.entries
	var count uint64
	var visitErr error
	emit := func(diff Diff) {
		count++
		if visitErr == nil && visit != nil {
			visitErr = visit(diff)
		}
	}
	for oldOK || newOK {
		switch {
		case !newOK || oldOK && oldEntry.Path < newEntry.Path:
			entry := oldEntry
			emit(Diff{Kind: DiffDeletion, Old: &entry})
			oldEntry, oldOK = <-oldStream.entries
		case !oldOK || newEntry.Path < oldEntry.Path:
			entry := newEntry
			emit(Diff{Kind: DiffAddition, New: &entry})
			newEntry, newOK = <-newStream.entries
		default:
			if oldEntry != newEntry {
				oldCopy, newCopy := oldEntry, newEntry
				emit(Diff{Kind: DiffChange, Old: &oldCopy, New: &newCopy})
			}
			oldEntry, oldOK = <-oldStream.entries
			newEntry, newOK = <-newStream.entries
		}
	}
	return count, errors.Join(visitErr, <-oldStream.done, <-newStream.done)
}
