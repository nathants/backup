package backup

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"backup/internal/format"
	"backup/internal/repository"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

var syncPublishedParent = unix.Fsync

type publicationError struct {
	err error
}

func (err *publicationError) Error() string   { return err.err.Error() }
func (err *publicationError) Unwrap() error   { return err.err }
func (err *publicationError) Published() bool { return true }

type packPartUnavailableError struct {
	packHash   string
	partNumber uint32
	failures   []string
}

func (err *packPartUnavailableError) Error() string {
	return fmt.Sprintf("part %d unavailable or corrupt on every mirror (%s)", err.partNumber, strings.Join(err.failures, "; "))
}

func markPublishedSyncError(err error) error {
	if err == nil {
		return nil
	}
	return &publicationError{err: err}
}

// Restore requires exclusive control of the destination namespace, including
// ancestors that could rename its directories, from planning through publication.
// No-follow checks do not synchronize with concurrent destination writers.
func Restore(ctx context.Context, options Options, request RestoreRequest) (RestoreResult, error) {
	result := RestoreResult{}
	if request.Pattern == "" {
		return result, fmt.Errorf("regular expression is required")
	}
	expression, err := regexp.Compile(request.Pattern)
	if err != nil {
		return result, fmt.Errorf("invalid regular expression: %w", err)
	}
	if request.TargetRoot == "" {
		return result, fmt.Errorf("restore target root is required")
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
	snapshot, err := resolveHistoryRevision(run.repo, history, request.Revision)
	if err != nil {
		return result, err
	}
	catalog := snapshot
	if request.CatalogRevision != "" {
		catalog, err = resolveHistoryRevision(run.repo, history, request.CatalogRevision)
		if err != nil {
			return result, err
		}
		snapshotPosition, snapshotFound, err := history.IndexOf(snapshot.CommitID)
		if err != nil {
			return result, err
		}
		catalogPosition, catalogFound, err := history.IndexOf(catalog.CommitID)
		if err != nil {
			return result, err
		}
		if !snapshotFound || !catalogFound || catalogPosition < snapshotPosition {
			return result, fmt.Errorf("catalog revision must be a descendant of the snapshot revision")
		}
		if err := repository.ValidateCatalogStateForSnapshot(snapshot.State, catalog.State); err != nil {
			return result, err
		}
	}
	result.SnapshotCommit, result.CatalogCommit = snapshot.CommitID, catalog.CommitID
	if request.Report != nil {
		if err := request.Report(RestoreEvent{Kind: RestoreResolved, SnapshotCommit: snapshot.CommitID, CatalogCommit: catalog.CommitID}); err != nil {
			return result, err
		}
	}
	targetFD, targetPath, err := openTargetRoot(request.TargetRoot)
	if err != nil {
		return result, err
	}
	defer func() { _ = unix.Close(targetFD) }()
	stage, err := os.MkdirTemp(run.options.statePath(), restoreTemporaryPrefix)
	if err != nil {
		return result, err
	}
	defer func() { _ = removeTreeNoFollow(stage) }()
	if err := os.Chmod(stage, 0o700); err != nil {
		return result, err
	}
	selection, conflicts, err := planRestoreSelection(snapshot.State, expression, targetFD, request.Overwrite, stage, request.Report, &result)
	if err != nil {
		return result, err
	}
	if request.DryRun {
		return result, nil
	}
	if conflicts {
		return result, fmt.Errorf("restore plan contains destination conflicts")
	}
	if result.Planned == 0 {
		return result, nil
	}
	if selection.regularCount != 0 {
		if err := prepareRestoreCatalogs(snapshot.State, selection); err != nil {
			return result, err
		}
		secretKey, err := run.secretKey(ctx)
		if err != nil {
			return result, err
		}
		if err := stageSelectedContentStream(ctx, run, catalog.State, secretKey, selection); err != nil {
			var unavailable *packPartUnavailableError
			if errors.As(err, &unavailable) && catalog.CommitID != head.CommitID && catalogHasRelocation(catalog.State, snapshot.State, head.State, unavailable.packHash, unavailable.partNumber) {
				return result, fmt.Errorf("%w; validated HEAD %s offers a compatible immutable relocation; retry explicitly with --catalog-revision %s", err, head.CommitID, head.CommitID)
			}
			return result, err
		}
		if err := verifyAllStagedStream(selection); err != nil {
			return result, err
		}
	}
	if err := publishRestoreSelection(targetFD, targetPath, selection, request.Overwrite, request.Report, &result); err != nil {
		return result, err
	}
	return result, nil
}

func openTargetRoot(value string) (int, string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return -1, "", err
	}
	fd, err := unix.Open(absolute, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open restore target root without following symlinks: %w", err)
	}
	return fd, absolute, nil
}

func destinationStatus(rootFD int, entry format.IndexEntry, overwrite bool) (string, error) {
	components := strings.Split(strings.TrimPrefix(entry.Path, "./"), "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(current) }()
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			return "new", nil
		}
		if openErr != nil {
			return "conflict", nil
		}
		_ = unix.Close(current)
		current = next
	}
	var stat unix.Stat_t
	err = unix.Fstatat(current, components[len(components)-1], &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return "new", nil
	}
	if err != nil {
		return "", err
	}
	compatible := entry.Kind == format.KindFile && stat.Mode&unix.S_IFMT == unix.S_IFREG || entry.Kind == format.KindSymlink && stat.Mode&unix.S_IFMT == unix.S_IFLNK
	if compatible && overwrite {
		return "overwrite", nil
	}
	return "conflict", nil
}

func catalogHasRelocation(current, snapshot, alternate repository.State, packHash string, partNumber uint32) bool {
	if repository.ValidateCatalogStateForSnapshot(snapshot, alternate) != nil {
		return false
	}
	currentPart, found, err := repository.FindPackPart(current, packHash, partNumber)
	if err != nil || !found {
		return false
	}
	alternatePart, found, err := repository.FindPackPart(alternate, packHash, partNumber)
	return err == nil && found && alternatePart.ObjectID != currentPart.ObjectID
}

func openOrCreateDestinationParent(rootFD int, path string) (int, string, error) {
	components := strings.Split(strings.TrimPrefix(path, "./"), "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", err
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(current, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, "", mkdirErr
			}
			if syncErr := unix.Fsync(current); syncErr != nil {
				_ = unix.Close(current)
				return -1, "", syncErr
			}
			next, openErr = unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		_ = unix.Close(current)
		if openErr != nil {
			return -1, "", fmt.Errorf("destination parent %q is not a safe directory: %w", component, openErr)
		}
		current = next
	}
	return current, components[len(components)-1], nil
}

func publishRegular(rootFD int, source string, entry format.IndexEntry, overwrite bool) error {
	parentFD, leaf, err := openOrCreateDestinationParent(rootFD, entry.Path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	status, err := destinationStatus(rootFD, entry, overwrite)
	if err != nil || status == "conflict" {
		if err != nil {
			return err
		}
		return fmt.Errorf("destination changed to a conflict")
	}
	temporary, fd, err := createAt(parentFD, 0o600)
	if err != nil {
		return err
	}
	published := false
	file := os.NewFile(uintptr(fd), temporary)
	defer func() {
		_ = file.Close()
		if !published {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	digest, _ := blake2b.New512(nil)
	written, copyErr := io.Copy(io.MultiWriter(file, digest), input)
	closeInputErr := input.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeInputErr != nil {
		return closeInputErr
	}
	if uint64(written) != entry.Size || hex.EncodeToString(digest.Sum(nil)) != strings.TrimPrefix(entry.Ref, "blake2b:") {
		return fmt.Errorf("verified staging changed while copying to destination")
	}
	if err := unix.Fchmod(fd, entry.Mode); err != nil {
		return err
	}
	times := []unix.Timespec{{Sec: 0, Nsec: unix.UTIME_OMIT}, unix.NsecToTimespec(entry.MtimeNS)}
	if err := unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("set destination timestamp through verified descriptor (requires Linux 5.8+): %w", err)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	// Detect replacement during the copy without following the temporary name.
	// This is defense in depth, not synchronization: the caller must exclusively
	// control the destination namespace through publication, including symlinks.
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(parentFD, temporary, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("inspect destination temporary before publication: %w", err)
	}
	if named.Dev != opened.Dev || named.Ino != opened.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("destination temporary file changed before publication")
	}
	if err := file.Close(); err != nil {
		return err
	}
	if overwrite {
		err = unix.Renameat(parentFD, temporary, parentFD, leaf)
	} else {
		err = unix.Renameat2(parentFD, temporary, parentFD, leaf, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return err
	}
	published = true
	return markPublishedSyncError(syncPublishedParent(parentFD))
}

func publishSymlink(rootFD int, entry format.IndexEntry, overwrite bool) error {
	parentFD, leaf, err := openOrCreateDestinationParent(rootFD, entry.Path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	status, err := destinationStatus(rootFD, entry, overwrite)
	if err != nil || status == "conflict" {
		if err != nil {
			return err
		}
		return fmt.Errorf("destination changed to a conflict")
	}
	linkRelative := strings.TrimPrefix(entry.Path, "./")
	targetRelative := strings.TrimPrefix(strings.TrimPrefix(entry.Ref, "target:"), "./")
	target, err := filepath.Rel(filepath.Dir(linkRelative), targetRelative)
	if err != nil || target == "" || filepath.IsAbs(target) {
		return fmt.Errorf("could not derive safe relative symlink target")
	}
	temporary, err := uniqueName()
	if err != nil {
		return err
	}
	if err := unix.Symlinkat(filepath.ToSlash(target), parentFD, temporary); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(parentFD, temporary, 0)
		}
	}()
	if overwrite {
		err = unix.Renameat(parentFD, temporary, parentFD, leaf)
	} else {
		err = unix.Renameat2(parentFD, temporary, parentFD, leaf, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return err
	}
	published = true
	return markPublishedSyncError(syncPublishedParent(parentFD))
}

func createAt(parentFD int, mode uint32) (string, int, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name, err := uniqueName()
		if err != nil {
			return "", -1, err
		}
		fd, err := unix.Openat(parentFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return name, fd, err
	}
	return "", -1, fmt.Errorf("could not allocate a unique destination temporary file")
}

func uniqueName() (string, error) {
	value, err := randomHex(16)
	if err != nil {
		return "", err
	}
	return ".backup-restore-" + value, nil
}
