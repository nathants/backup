package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/pack"
	"backup/internal/repository"

	"github.com/nathants/go-libsodium"
	"golang.org/x/sys/unix"
)

const maximumDisplayedCaptureWarnings = 100

func (run *runtime) capturePlan(ctx context.Context, txn *transaction, base repository.State) (noChanges bool, returnErr error) {
	if txn == nil || txn.Plan == nil || len(txn.CandidateFiles) != 0 {
		return false, fmt.Errorf("transaction does not contain an uncaptured add plan")
	}
	if err := run.requirePlanOutsideFilesystemMirrors(txn.Plan, run.config); err != nil {
		return false, err
	}
	configBlobs := make(map[string][]byte, 3)
	for _, name := range []string{"ignore", ".publickeys", "mirrors.tsv"} {
		planned, err := run.readPlanConfig(txn, name)
		if err != nil {
			return false, err
		}
		configBlobs[name] = planned
		current, err := readRegularNoFollow(filepath.Join(run.repo.Directory, name), configurationByteLimit(name))
		if err != nil {
			return false, fmt.Errorf("read metadata configuration %q: %w", name, err)
		}
		if !bytes.Equal(current, planned) {
			return false, fmt.Errorf("metadata configuration %q changed after add; run add again", name)
		}
	}
	publicKeys, err := libsodium.ParseKeyChains(bytes.NewReader(configBlobs[".publickeys"]))
	if err != nil {
		return false, err
	}
	if err := libsodium.ValidateKeyChainTransition(base.PublicKeys, publicKeys); err != nil {
		return false, err
	}
	mirrors, err := format.ParseMirrors(bytes.NewReader(configBlobs["mirrors.tsv"]), configurationLimits("mirrors.tsv"))
	if err != nil {
		return false, err
	}
	if err := run.config.RequireCanonicalMirrors(mirrors); err != nil {
		return false, err
	}
	ledger, err := run.loadLedger(base.Format.RepositoryUUID)
	if err != nil {
		return false, err
	}
	if err := run.requireBackupEligibility(txn, ledger); err != nil {
		return false, err
	}
	if txn.Capture != nil {
		if err := run.revalidateCapture(ctx, txn, ledger); err != nil {
			return false, err
		}
	}
	if txn.Capture == nil {
		txn.Incident = ledger.Incident
		eligible := make(map[string]bool)
		for _, mirror := range run.config.Mirrors {
			if ledger.Mirrors[mirror.Canonical.Name] == txn.BaseCommit {
				eligible[mirror.Canonical.Name] = true
			}
		}
		if len(eligible) == 0 {
			return false, fmt.Errorf("no mirror is durably known complete through the add-plan base; audit and sync a mirror first")
		}
		txn.Capture = &captureProgress{Mirrors: eligible}
		if err := run.saveTransaction(txn); err != nil {
			return false, err
		}
		if err := run.checkpoint("commit-capture-started"); err != nil {
			return false, err
		}
	}
	captureDirectory := filepath.Join(run.options.transactionFilesPath(), "capture")
	if err := removeTreeNoFollow(captureDirectory); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := ensurePrivateDirectory(captureDirectory); err != nil {
		return false, err
	}
	root, err := filesystem.OpenRoot(run.options.Root)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	plainSpool, err := run.preparePlaintextSpool(root.Path, captureDirectory, base.Format.RepositoryUUID)
	if err != nil {
		return false, errors.Join(err, removeTreeIfPresent(captureDirectory))
	}
	defer func() {
		cleanupErr := errors.Join(plainSpool.CloseAndRemove(), removeTreeIfPresent(captureDirectory))
		if returnErr == nil && cleanupErr != nil {
			returnErr = fmt.Errorf("clean capture staging: %w", cleanupErr)
		}
	}()

	dedup, err := run.prepareCaptureDedup(filepath.Join(captureDirectory, "dedup.index"), txn, base)
	if err != nil {
		return false, err
	}
	defer func() { _ = dedup.Close() }()
	var pendingIndex []format.IndexEntry
	var builder *pack.StreamBuilder
	var builderSize uint64
	var builderMembers int
	currentHashes := make(map[string]uint64)
	packMirrors := copyBoolSet(txn.Capture.Mirrors)
	pendingWarnings := uint64(0)

	persist := func(end int, created *pack.Created) error {
		if created != nil {
			txn.Capture.Mirrors = copyBoolSet(packMirrors)
		}
		if ^uint64(0)-txn.Capture.Warnings < pendingWarnings {
			return fmt.Errorf("capture warning count overflow")
		}
		txn.Capture.Warnings += pendingWarnings
		start := txn.Capture.NextPlan
		if err := run.writeCaptureSegment(txn, start, end, pendingIndex, created); err != nil {
			return err
		}
		pendingIndex = nil
		pendingWarnings = 0
		run.options.progress.eventf("capture checkpoint: saved paths=%d/%d eligible-mirrors=%v (revision not yet published)", end, txn.Plan.Entries, sortedMirrorNames(txn.Capture.Mirrors))
		return run.checkpoint("completed-pack-recorded")
	}
	closePack := func(end int) (returnErr error) {
		if builder == nil {
			return persist(end, nil)
		}
		created, err := builder.Close()
		builder = nil
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, created.Remove()) }()
		for _, object := range created.Objects {
			if err := dedup.Insert(object.PlaintextHash, object.PlaintextSize); err != nil {
				return err
			}
		}
		builderSize, builderMembers = 0, 0
		clear(currentHashes)
		return persist(end, &created)
	}
	abort := func() {
		if builder != nil {
			builder.Abort()
		}
	}
	defer abort()

	const maximumPathsPerCaptureSegment = 10_000
	run.options.progress.phasef("capturing and uploading planned paths")
	run.options.progress.eventf("resuming capture at saved position=%d/%d", txn.Capture.NextPlan, txn.Plan.Entries)
	processPlanned := func(position int, planned format.IndexEntry) error {
		finish := func() error {
			if position+1-txn.Capture.NextPlan < maximumPathsPerCaptureSegment {
				return nil
			}
			if err := closePack(position + 1); err != nil {
				return err
			}
			packMirrors = copyBoolSet(txn.Capture.Mirrors)
			return nil
		}
		run.options.progress.detailf("capture processed paths=%d/%d", position, txn.Plan.Entries)
		captured, err := root.CapturePath(planned, plainSpool, run.options.SpaceReserveBytes)
		if err != nil {
			return err
		}
		if captured.Entry == nil {
			// Omissions affect snapshot coverage, not just which version of a
			// file was captured. Never hide them behind the mutation warning cap.
			if err := run.reportf("warning: %s: %s\n", terminalEscape(planned.Path), terminalEscape(captured.Reason)); err != nil {
				return err
			}
			return finish()
		}
		if captured.Changed {
			if pendingWarnings == ^uint64(0) {
				return fmt.Errorf("pending capture warning count overflow")
			}
			pendingWarnings++
			if txn.Capture.WarningsShown < maximumDisplayedCaptureWarnings {
				if err := run.reportf("warning: %s: %s\n", terminalEscape(planned.Path), terminalEscape(captured.Reason)); err != nil {
					return err
				}
				txn.Capture.WarningsShown++
				if err := run.saveTransaction(txn); err != nil {
					return err
				}
			}
		}
		entry := *captured.Entry
		if entry.Kind != format.KindFile {
			pendingIndex = append(pendingIndex, entry)
			return finish()
		}
		if captured.Plain == nil {
			return fmt.Errorf("regular capture did not return a plaintext spool file")
		}
		hash := strings.TrimPrefix(entry.Ref, "blake2b:")
		exists, err := dedup.Contains(hash, entry.Size)
		if err != nil {
			_ = captured.Plain.Remove()
			return err
		}
		if exists {
			if err := captured.Plain.Remove(); err != nil {
				return err
			}
			pendingIndex = append(pendingIndex, entry)
			return finish()
		}
		if currentSize, ok := currentHashes[hash]; ok {
			if currentSize != entry.Size {
				_ = captured.Plain.Remove()
				return fmt.Errorf("current pack object %s has conflicting size", hash)
			}
			if err := captured.Plain.Remove(); err != nil {
				return err
			}
			pendingIndex = append(pendingIndex, entry)
			return finish()
		}
		wouldExceed := entry.Size > run.options.PackTarget || builderSize > run.options.PackTarget-entry.Size || builderMembers >= pack.MaximumMembersPerPack
		if builder != nil && wouldExceed {
			if err := closePack(position); err != nil {
				_ = captured.Plain.Remove()
				return err
			}
			packMirrors = copyBoolSet(txn.Capture.Mirrors)
		}
		if builder == nil {
			stage := filepath.Join(captureDirectory, "active-pack")
			if err := ensurePrivateDirectory(stage); err != nil {
				_ = captured.Plain.Remove()
				return err
			}
			partSize, err := boundedCiphertextPartSize(stage, run.options.PartSize, run.options.SpaceReserveBytes)
			if err != nil {
				_ = captured.Plain.Remove()
				return err
			}
			builder, err = pack.NewStreamBuilder(publicKeys, stage, partSize, func(part *pack.StreamPart) error {
				return run.uploadCapturedPart(ctx, part, &packMirrors)
			})
			if err != nil {
				_ = captured.Plain.Remove()
				return err
			}
		}
		pendingIndex = append(pendingIndex, entry)
		if err := builder.Add(pack.StagedFile{Hash: hash, Size: entry.Size, Open: captured.Plain.File}); err != nil {
			_ = captured.Plain.Remove()
			return err
		}
		currentHashes[hash] = entry.Size
		if err := captured.Plain.Remove(); err != nil {
			return fmt.Errorf("remove consumed plaintext spool: %w", err)
		}
		builderSize += entry.Size
		builderMembers++
		if entry.Size > run.options.PackTarget {
			if err := closePack(position + 1); err != nil {
				return err
			}
			packMirrors = copyBoolSet(txn.Capture.Mirrors)
			return nil
		}
		return finish()
	}
	if err := run.walkPlan(txn, txn.Capture.NextPlan, processPlanned); err != nil {
		return false, err
	}
	if err := closePack(txn.Plan.Entries); err != nil {
		return false, err
	}
	if txn.Capture.Warnings > txn.Capture.WarningsShown && !txn.Capture.WarningSummary {
		if err := run.reportf("warning: %d additional planned paths changed during commit\n", txn.Capture.Warnings-txn.Capture.WarningsShown); err != nil {
			return false, err
		}
		txn.Capture.WarningSummary = true
		if err := run.saveTransaction(txn); err != nil {
			return false, err
		}
	}
	if txn.Capture.Entries == 0 && !txn.Plan.AllowEmpty {
		return false, fmt.Errorf("every path selected by add disappeared, became inaccessible, or became unsupported; rerun add or use add --allow-empty")
	}
	return run.finalizeCapture(txn, base)
}

func (run *runtime) uploadCapturedPart(ctx context.Context, part *pack.StreamPart, candidateMirrors *map[string]bool) error {
	if part == nil || candidateMirrors == nil || len(*candidateMirrors) == 0 {
		return fmt.Errorf("no complete-through-base mirror remains for ciphertext part")
	}
	fd, err := unix.Open(part.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), part.Path)
	defer func() { _ = file.Close() }()
	expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
	key, err := format.ObjectKey(part.Hash, part.ObjectID)
	if err != nil {
		return err
	}
	acknowledged := make(map[string]bool)
	for name := range *candidateMirrors {
		mirror, ok := run.mirror(name)
		if !ok {
			continue
		}
		writer, err := run.client(ctx, mirror)
		if err != nil {
			if reportErr := run.reportf("mirror %s data upload unavailable: %s\n", name, terminalEscape(err.Error())); reportErr != nil {
				return reportErr
			}
			continue
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		run.options.progress.eventf("uploading ciphertext to mirror %s; part bytes=%d", name, part.Size)
		result := writer.PutOpenFile(ctx, key, file, expected)
		if result.Disposition == objectstore.CreateAcknowledged || (result.Disposition == objectstore.CreateConflict || result.Disposition == objectstore.CreateAmbiguous) && run.auditObject(ctx, mirror, key, expected) == nil {
			run.options.progress.eventf("mirror %s acknowledged ciphertext part bytes=%d", name, part.Size)
			acknowledged[name] = true
			continue
		}
		if err := run.reportf("mirror %s did not acknowledge data object %s: %s\n", name, key, terminalEscape(errorText(result.Err))); err != nil {
			return err
		}
	}
	if len(acknowledged) == 0 {
		return fmt.Errorf("no individual mirror acknowledged ciphertext part %s", key)
	}
	*candidateMirrors = acknowledged
	return nil
}

func (run *runtime) finalizeCapture(txn *transaction, base repository.State) (bool, error) {
	run.options.progress.phasef("building and validating captured catalogs")
	if err := run.buildCandidateFiles(txn, base); err != nil {
		return false, err
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		return false, err
	}
	if candidate.Equal(base) {
		return true, nil
	}
	if transition, err := repository.ValidateTransition(base, candidate); err != nil || transition != repository.TransitionOrdinary {
		if err != nil {
			return false, err
		}
		return false, fmt.Errorf("captured candidate is not an ordinary transition")
	}
	if len(txn.Capture.Mirrors) == 0 {
		return false, fmt.Errorf("captured candidate has no individually complete mirror")
	}
	for name := range txn.Capture.Mirrors {
		progress := txn.progress(name)
		progress.DataComplete = true
	}
	if err := run.saveTransaction(txn); err != nil {
		return false, err
	}
	if err := run.checkpoint("commit-capture-finalized"); err != nil {
		return false, err
	}
	return false, nil
}

func (run *runtime) cleanupInterruptedPlaintextSpool(txn *transaction) error {
	if run.options.SpoolDirectory == "" || txn == nil || txn.Capture == nil || txn.BaseCommit == "" {
		return nil
	}
	history, err := (repository.Validator{Repo: run.repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(txn.BaseCommit)
	if err != nil {
		return err
	}
	defer func() { _ = history.Close() }()
	tip, err := history.Tip()
	if err != nil {
		return err
	}
	root, err := filesystem.OpenRoot(run.options.Root)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	spool, err := run.preparePlaintextSpool(root.Path, filepath.Join(run.options.transactionFilesPath(), "capture"), tip.State.Format.RepositoryUUID)
	if err != nil {
		return err
	}
	return spool.CloseAndRemove()
}

func (run *runtime) preparePlaintextSpool(rootPath, captureDirectory, repositoryUUID string) (*filesystem.Spool, error) {
	parent, child := captureDirectory, "plaintext"
	if run.options.SpoolDirectory != "" {
		parent = run.options.SpoolDirectory
		metadataRoot := filepath.Join(rootPath, metadataRepositoryName)
		if pathWithin(rootPath, parent) && !pathWithin(metadataRoot, parent) {
			return nil, fmt.Errorf("external plaintext spool %q is inside the backup root but outside excluded metadata state", parent)
		}
		digest := sha256.Sum256([]byte(rootPath + "\x00" + repositoryUUID))
		child = fmt.Sprintf(".backup-spool-%s-%x", strings.ReplaceAll(repositoryUUID, "-", ""), digest[:8])
	}
	spool, err := filesystem.PrepareSpool(parent, child)
	if err != nil {
		return nil, err
	}
	return spool, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func boundedCiphertextPartSize(directory string, configured, reserveBytes uint64) (uint64, error) {
	availableBytes, availableInodes, err := filesystem.DirectoryCapacity(directory)
	if err != nil {
		return 0, fmt.Errorf("inspect ciphertext staging capacity: %w", err)
	}
	return chooseCiphertextPartSize(configured, reserveBytes, availableBytes, availableInodes)
}

func boundedMetadataStaging(directory string, configured, reserveBytes uint64) (uint64, uint64, error) {
	availableBytes, availableInodes, err := filesystem.DirectoryCapacity(directory)
	if err != nil {
		return 0, 0, fmt.Errorf("inspect metadata staging capacity: %w", err)
	}
	partSize, err := chooseCiphertextPartSize(configured, reserveBytes, availableBytes, availableInodes)
	if err != nil {
		return 0, 0, err
	}
	return partSize, availableBytes - reserveBytes, nil
}

func requireWorkspaceCapacity(directory string, additionalBytes, additionalInodes, reserveBytes uint64) error {
	availableBytes, availableInodes, err := filesystem.DirectoryCapacity(directory)
	if err != nil {
		return err
	}
	if additionalBytes > ^uint64(0)-reserveBytes || availableBytes < additionalBytes+reserveBytes {
		return fmt.Errorf("workspace needs %d additional bytes while retaining a %d-byte reserve, but only %d bytes are available", additionalBytes, reserveBytes, availableBytes)
	}
	const inodeHeadroom = uint64(16)
	if additionalInodes > ^uint64(0)-inodeHeadroom || availableInodes < additionalInodes+inodeHeadroom {
		return fmt.Errorf("workspace needs %d additional inodes while retaining %d free inodes, but only %d are available", additionalInodes, inodeHeadroom, availableInodes)
	}
	return nil
}

func chooseCiphertextPartSize(configured, reserveBytes, availableBytes, availableInodes uint64) (uint64, error) {
	const inodeHeadroom = uint64(16)
	if availableInodes <= inodeHeadroom {
		return 0, fmt.Errorf("ciphertext staging has %d free inodes; need one part inode while retaining %d", availableInodes, inodeHeadroom)
	}
	if availableBytes <= reserveBytes {
		return 0, fmt.Errorf("ciphertext staging has %d available bytes, not enough to retain the %d-byte reserve", availableBytes, reserveBytes)
	}
	safe := availableBytes - reserveBytes
	if configured < safe {
		safe = configured
	}
	if safe == 0 || safe > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("safe ciphertext part size %d is not representable", safe)
	}
	return safe, nil
}

func removeTreeIfPresent(path string) error {
	err := removeTreeNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func copyBoolSet(input map[string]bool) map[string]bool {
	result := make(map[string]bool, len(input))
	for key, value := range input {
		if value {
			result[key] = true
		}
	}
	return result
}
