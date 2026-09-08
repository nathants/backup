package filesystem

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

type EventKind string

const (
	EventMountEntered   EventKind = "mount-entered"
	EventSpecialSkipped EventKind = "special-skipped"
	EventBrokenSymlink  EventKind = "broken-symlink-skipped"
	EventOutsideSymlink EventKind = "outside-symlink-skipped"
)

type Event struct {
	Kind EventKind
	Path string
}

type Reporter func(Event)

var errCaptureRace = errors.New("source changed during capture classification")

type Identity struct {
	Device   uint64
	Inode    uint64
	Size     uint64
	Mode     uint32
	MtimeSec int64
	MtimeNS  int64
	CtimeSec int64
	CtimeNS  int64
}

type File struct {
	Hash string
	Size uint64
}

type Result struct {
	Entries                uint64
	SkippedSpecial         uint64
	SkippedBrokenSymlinks  uint64
	SkippedOutsideSymlinks uint64
	MountsEntered          uint64
}

type CaptureResult struct {
	Entry   *format.IndexEntry
	Plain   *SpoolFile
	Changed bool
	Reason  string
}

type Root struct {
	Path              string
	fd                int
	once              sync.Once
	err               error
	captureBeforeOpen func(string) error
	captureOpened     func(string) error
	symlinkOpened     func() error
}

func OpenRoot(path string) (*Root, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve backup root: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve backup root symlinks: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return nil, fmt.Errorf("stat backup root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("backup root is not a directory")
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open backup root: %w", err)
	}
	return &Root{Path: canonical, fd: fd}, nil
}

func (root *Root) Close() error {
	if root == nil {
		return nil
	}
	root.once.Do(func() {
		if root.fd >= 0 {
			root.err = unix.Close(root.fd)
			root.fd = -1
		}
	})
	return root.err
}

// Walk scans and hashes every selected regular file while emitting canonical
// entries in deterministic traversal order. It retains no path or content
// catalog; callers that require canonical lexical order externally sort rows.
func (root *Root) Walk(ignore format.Ignore, reporter Reporter, visit func(*File, format.IndexEntry) error) (Result, error) {
	if visit == nil {
		return Result{}, fmt.Errorf("scan visitor is required")
	}
	return root.walk(ignore, reporter, visit)
}

func (root *Root) walk(ignore format.Ignore, reporter Reporter, visit func(*File, format.IndexEntry) error) (Result, error) {
	if root == nil || root.fd < 0 {
		return Result{}, fmt.Errorf("backup root is closed")
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(root.fd, &rootStat); err != nil {
		return Result{}, fmt.Errorf("stat backup root descriptor: %w", err)
	}
	result := Result{}
	if err := root.scanDirectory(root.fd, "", uint64(rootStat.Dev), ignore, reporter, &result, visit); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (root *Root) scanDirectory(directoryFD int, relative string, parentDevice uint64, ignore format.Ignore, reporter Reporter, result *Result, visit func(*File, format.IndexEntry) error) (returnErr error) {
	copyFD, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(copyFD), relative)
	defer func() {
		if closeErr := directory.Close(); returnErr == nil {
			returnErr = closeErr
		}
	}()
	for {
		entries, readErr := directory.ReadDir(256)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read directory %q: %w", displayPath(relative), readErr)
		}
		for _, entry := range entries {
			name := entry.Name()
			childRelative := name
			if relative != "" {
				childRelative = relative + "/" + name
			}
			indexPath := "./" + childRelative
			if err := format.ValidatePath(indexPath); err != nil {
				return fmt.Errorf("invalid source path %q: %w", indexPath, err)
			}
			if indexPath == "./.backup" || strings.HasPrefix(indexPath, "./.backup/") || root.defaultExcluded(indexPath) || ignore.Match(indexPath) {
				continue
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("stat source %q: %w", indexPath, err)
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				childFD, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					return fmt.Errorf("open source directory %q: %w", indexPath, err)
				}
				if uint64(stat.Dev) != parentDevice {
					result.MountsEntered++
					report(reporter, Event{Kind: EventMountEntered, Path: indexPath})
				}
				err = root.scanDirectory(childFD, childRelative, uint64(stat.Dev), ignore, reporter, result, visit)
				_ = unix.Close(childFD)
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				file, indexEntry, err := root.scanRegular(directoryFD, name, indexPath, stat)
				if err != nil {
					return err
				}
				if err := visit(&file, indexEntry); err != nil {
					return err
				}
				result.Entries++
			case unix.S_IFLNK:
				indexEntry, skipKind, err := root.scanSymlink(directoryFD, name, indexPath, stat)
				if err != nil {
					return err
				}
				if indexEntry != nil {
					if err := visit(nil, *indexEntry); err != nil {
						return err
					}
					result.Entries++
					continue
				}
				switch skipKind {
				case EventBrokenSymlink:
					result.SkippedBrokenSymlinks++
				case EventOutsideSymlink:
					result.SkippedOutsideSymlinks++
				}
				report(reporter, Event{Kind: skipKind, Path: indexPath})
			default:
				result.SkippedSpecial++
				report(reporter, Event{Kind: EventSpecialSkipped, Path: indexPath})
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func (root *Root) scanRegular(directoryFD int, name, indexPath string, directoryStat unix.Stat_t) (File, format.IndexEntry, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("open source file %q: %w", indexPath, err)
	}
	file := os.NewFile(uintptr(fd), indexPath)
	defer func() { _ = file.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("stat open source file %q: %w", indexPath, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Dev != directoryStat.Dev || before.Ino != directoryStat.Ino {
		return File{}, format.IndexEntry{}, fmt.Errorf("source file %q changed type or identity during scan", indexPath)
	}
	identity, err := identityFromStat(before)
	if err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("source file %q: %w", indexPath, err)
	}
	hash, _ := blake2b.New512(nil)
	count, err := io.CopyBuffer(hash, file, make([]byte, 1<<20))
	if err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("read source file %q: %w", indexPath, err)
	}
	if uint64(count) != identity.Size {
		return File{}, format.IndexEntry{}, fmt.Errorf("source file %q changed size while hashing", indexPath)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("restat source file %q: %w", indexPath, err)
	}
	afterIdentity, err := identityFromStat(after)
	if err != nil || afterIdentity != identity {
		return File{}, format.IndexEntry{}, fmt.Errorf("source file %q changed while hashing", indexPath)
	}
	hashText := fmt.Sprintf("%x", hash.Sum(nil))
	mtimeNanoseconds, err := checkedTimespec(identity.MtimeSec, identity.MtimeNS)
	if err != nil {
		return File{}, format.IndexEntry{}, fmt.Errorf("source file %q mtime: %w", indexPath, err)
	}
	return File{Hash: hashText, Size: identity.Size}, format.IndexEntry{
		Path: indexPath, Kind: format.KindFile, Ref: "blake2b:" + hashText, Size: identity.Size,
		Mode: identity.Mode, MtimeNS: mtimeNanoseconds,
	}, nil
}

func (root *Root) scanSymlink(directoryFD int, name, indexPath string, before unix.Stat_t) (*format.IndexEntry, EventKind, error) {
	// Resolve relative to the already-open parent so an ancestor rename or swap
	// cannot redirect the lookup. Absolute targets retain normal Linux semantics
	// and are rooted at /, not at the backup root.
	targetBefore, err := readSymlinkAt(directoryFD, name)
	if err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
			return nil, "", fmt.Errorf("source symlink %q changed during scan: %w", indexPath, errCaptureRace)
		}
		return nil, "", fmt.Errorf("read source symlink %q: %w", indexPath, err)
	}
	how := &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_MAGICLINKS}
	fd, resolveErr := unix.Openat2(directoryFD, name, how)
	if resolveErr == nil {
		defer func() { _ = unix.Close(fd) }()
		if root.symlinkOpened != nil {
			if err := root.symlinkOpened(); err != nil {
				return nil, "", err
			}
		}
	}

	targetAfter, readErr := readSymlinkAt(directoryFD, name)
	var after unix.Stat_t
	statErr := unix.Fstatat(directoryFD, name, &after, unix.AT_SYMLINK_NOFOLLOW)
	if readErr != nil || statErr != nil || targetBefore != targetAfter || !sameSymlink(before, after) {
		return nil, "", fmt.Errorf("source symlink %q changed during scan: %w", indexPath, errCaptureRace)
	}
	if resolveErr != nil {
		switch {
		case errors.Is(resolveErr, unix.ENOENT), errors.Is(resolveErr, unix.ELOOP):
			if symlinkTargetOutsideRoot(root.Path, indexPath, targetBefore) {
				return nil, EventOutsideSymlink, nil
			}
			return nil, EventBrokenSymlink, nil
		case errors.Is(resolveErr, unix.EXDEV):
			return nil, EventOutsideSymlink, nil
		case errors.Is(resolveErr, unix.ENOSYS):
			return nil, "", fmt.Errorf("openat2 is required for safe symlink scanning")
		default:
			return nil, "", fmt.Errorf("resolve source symlink %q: %w", indexPath, resolveErr)
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, "", fmt.Errorf("stat source symlink target %q: %w", indexPath, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, EventBrokenSymlink, nil
	}
	resolved, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, "", fmt.Errorf("read resolved source symlink %q: %w", indexPath, err)
	}
	if stat.Nlink == 0 {
		return nil, "", fmt.Errorf("source symlink %q changed during scan: %w", indexPath, errCaptureRace)
	}
	// /proc appends " (deleted)" to an unlinked dentry, but that is also a
	// legal filename. Another hardlink can keep Nlink nonzero (even at that
	// exact printable name). Re-resolve the original link and require both the
	// same inode and descriptor path, rather than guessing from the suffix.
	currentFD, err := unix.Openat2(directoryFD, name, how)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			return nil, "", fmt.Errorf("source symlink %q changed during scan: %w", indexPath, errCaptureRace)
		}
		return nil, "", fmt.Errorf("recheck source symlink %q: %w", indexPath, err)
	}
	defer func() { _ = unix.Close(currentFD) }()
	var current unix.Stat_t
	if err := unix.Fstat(currentFD, &current); err != nil {
		return nil, "", fmt.Errorf("restat source symlink target %q: %w", indexPath, err)
	}
	currentPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", currentFD))
	if err != nil {
		return nil, "", fmt.Errorf("reread resolved source symlink %q: %w", indexPath, err)
	}
	if current.Nlink == 0 || current.Dev != stat.Dev || current.Ino != stat.Ino || currentPath != resolved {
		return nil, "", fmt.Errorf("source symlink %q changed during scan: %w", indexPath, errCaptureRace)
	}
	targetRelative, err := filepath.Rel(root.Path, resolved)
	if err != nil || targetRelative == ".." || strings.HasPrefix(targetRelative, ".."+string(filepath.Separator)) {
		return nil, EventOutsideSymlink, nil
	}
	targetPath := "./"
	if targetRelative != "." {
		targetPath += filepath.ToSlash(targetRelative)
	}
	if err := format.ValidateSymlinkTarget(targetPath); err != nil {
		return nil, "", fmt.Errorf("invalid source symlink target %q for %q: %w", targetPath, indexPath, err)
	}
	return &format.IndexEntry{Path: indexPath, Kind: format.KindSymlink, Ref: "target:" + targetPath}, "", nil
}

func readSymlinkAt(directoryFD int, name string) (string, error) {
	buffer := make([]byte, 4097)
	count, err := unix.Readlinkat(directoryFD, name, buffer)
	if err != nil {
		return "", err
	}
	if count == len(buffer) {
		return "", fmt.Errorf("symlink target is too long")
	}
	return string(buffer[:count]), nil
}

func sameSymlink(left, right unix.Stat_t) bool {
	return left.Mode&unix.S_IFMT == unix.S_IFLNK && right.Mode&unix.S_IFMT == unix.S_IFLNK &&
		left.Dev == right.Dev && left.Ino == right.Ino && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func symlinkTargetOutsideRoot(rootPath, indexPath, target string) bool {
	var absolute string
	if filepath.IsAbs(target) {
		absolute = filepath.Clean(target)
	} else {
		linkRelative := strings.TrimPrefix(indexPath, "./")
		absolute = filepath.Clean(filepath.Join(rootPath, filepath.Dir(linkRelative), target))
	}
	relative, err := filepath.Rel(rootPath, absolute)
	return err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (root *Root) CapturePath(planned format.IndexEntry, spool *Spool, reserveBytes uint64) (CaptureResult, error) {
	for attempt := 0; attempt < 3; attempt++ {
		captured, err := root.capturePathOnce(planned, spool, reserveBytes)
		if !errors.Is(err, errCaptureRace) {
			return captured, err
		}
	}
	return CaptureResult{}, fmt.Errorf("planned source %q changed repeatedly while being opened", planned.Path)
}

func (root *Root) capturePathOnce(planned format.IndexEntry, spool *Spool, reserveBytes uint64) (CaptureResult, error) {
	if root == nil || root.fd < 0 {
		return CaptureResult{}, fmt.Errorf("backup root is closed")
	}
	if spool == nil || spool.fd < 0 {
		return CaptureResult{}, fmt.Errorf("plaintext spool is closed")
	}
	if err := format.ValidatePath(planned.Path); err != nil {
		return CaptureResult{}, err
	}
	parentFD, name, err := root.openParent(planned.Path)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return CaptureResult{Changed: true, Reason: "removed since add; omitted"}, nil
		}
		return CaptureResult{}, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	var pathStat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return CaptureResult{Changed: true, Reason: "removed since add; omitted"}, nil
		}
		return CaptureResult{}, fmt.Errorf("stat planned source %q: %w", planned.Path, err)
	}
	switch pathStat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return root.captureRegular(parentFD, name, planned, pathStat, spool, reserveBytes)
	case unix.S_IFLNK:
		entry, skip, err := root.scanSymlink(parentFD, name, planned.Path, pathStat)
		if err != nil {
			return CaptureResult{}, err
		}
		if entry == nil {
			reason := "symlink became unavailable; omitted"
			if skip == EventOutsideSymlink {
				reason = "symlink now resolves outside the backup root; omitted"
			}
			return CaptureResult{Changed: true, Reason: reason}, nil
		}
		return CaptureResult{Entry: entry, Changed: *entry != planned, Reason: "changed since add; captured current symlink"}, nil
	default:
		return CaptureResult{Changed: true, Reason: "changed to an unsupported type; omitted"}, nil
	}
}

func (root *Root) captureRegular(parentFD int, name string, planned format.IndexEntry, classified unix.Stat_t, spool *Spool, reserveBytes uint64) (CaptureResult, error) {
	if root.captureBeforeOpen != nil {
		if err := root.captureBeforeOpen(planned.Path); err != nil {
			return CaptureResult{}, err
		}
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		var current unix.Stat_t
		statErr := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW)
		changed := errors.Is(statErr, unix.ENOENT) || statErr == nil &&
			(current.Dev != classified.Dev || current.Ino != classified.Ino || current.Mode&unix.S_IFMT != classified.Mode&unix.S_IFMT)
		if changed {
			return CaptureResult{}, errCaptureRace
		}
		return CaptureResult{}, fmt.Errorf("open planned source %q: %w", planned.Path, err)
	}
	source := os.NewFile(uintptr(fd), planned.Path)
	defer func() { _ = source.Close() }()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return CaptureResult{}, fmt.Errorf("stat open planned source %q: %w", planned.Path, err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return CaptureResult{}, errCaptureRace
	}
	identity, err := identityFromStat(before)
	if err != nil {
		return CaptureResult{}, err
	}
	temporary, err := spool.Create(planned.Path, identity.Size, reserveBytes)
	if err != nil {
		return CaptureResult{}, err
	}
	if root.captureOpened != nil {
		if err := root.captureOpened(planned.Path); err != nil {
			_ = temporary.Remove()
			return CaptureResult{}, err
		}
	}
	keep := false
	defer func() {
		if !keep {
			_ = temporary.Remove()
		}
	}()
	hash, _ := blake2b.New512(nil)
	limited := &io.LimitedReader{R: source, N: int64(identity.Size)}
	count, err := io.CopyBuffer(io.MultiWriter(temporary.File, hash), limited, make([]byte, 1<<20))
	if err != nil {
		return CaptureResult{}, fmt.Errorf("capture planned source %q: %w", planned.Path, err)
	}
	if err := temporary.Sync(); err != nil {
		return CaptureResult{}, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return CaptureResult{}, fmt.Errorf("restat planned source %q: %w", planned.Path, err)
	}
	afterIdentity, afterErr := identityFromStat(after)
	mtime, err := checkedTimespec(identity.MtimeSec, identity.MtimeNS)
	if err != nil {
		return CaptureResult{}, err
	}
	hashText := fmt.Sprintf("%x", hash.Sum(nil))
	entry := format.IndexEntry{Path: planned.Path, Kind: format.KindFile, Ref: "blake2b:" + hashText, Size: uint64(count), Mode: identity.Mode, MtimeNS: mtime}
	mutated := afterErr != nil || afterIdentity != identity || uint64(count) != identity.Size
	changed := entry != planned || mutated
	reason := "changed since add; captured current bytes"
	if mutated {
		reason = "changed while being captured; committed the bytes read"
	}
	keep = true
	return CaptureResult{Entry: &entry, Plain: temporary, Changed: changed, Reason: reason}, nil
}

func (root *Root) openParent(indexPath string) (int, string, error) {
	components := strings.Split(strings.TrimPrefix(indexPath, "./"), "/")
	currentFD, err := unix.Dup(root.fd)
	if err != nil {
		return -1, "", err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return -1, "", fmt.Errorf("open source parent for %q: %w", indexPath, openErr)
		}
		currentFD = nextFD
	}
	return currentFD, components[len(components)-1], nil
}

func identityFromStat(stat unix.Stat_t) (Identity, error) {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 {
		return Identity{}, fmt.Errorf("not a regular file")
	}
	_, err := checkedTimespec(stat.Mtim.Sec, stat.Mtim.Nsec)
	if err != nil {
		return Identity{}, fmt.Errorf("mtime: %w", err)
	}
	if _, err := checkedTimespec(stat.Ctim.Sec, stat.Ctim.Nsec); err != nil {
		return Identity{}, fmt.Errorf("ctime: %w", err)
	}
	return Identity{
		Device: uint64(stat.Dev), Inode: stat.Ino, Size: uint64(stat.Size), Mode: stat.Mode & 0o777,
		MtimeSec: stat.Mtim.Sec, MtimeNS: stat.Mtim.Nsec, CtimeSec: stat.Ctim.Sec, CtimeNS: stat.Ctim.Nsec,
	}, nil
}

func checkedTimespec(seconds, nanoseconds int64) (int64, error) {
	if nanoseconds < 0 || nanoseconds >= 1_000_000_000 {
		return 0, fmt.Errorf("invalid nanoseconds")
	}
	if seconds < -9_223_372_037 || seconds > 9_223_372_036 {
		return 0, fmt.Errorf("timestamp is outside int64 nanoseconds")
	}
	if seconds == 9_223_372_036 && nanoseconds > 854_775_807 {
		return 0, fmt.Errorf("timestamp is outside int64 nanoseconds")
	}
	if seconds == -9_223_372_037 {
		if nanoseconds < 145_224_192 {
			return 0, fmt.Errorf("timestamp is outside int64 nanoseconds")
		}
		return -9_223_372_036_854_775_808 + (nanoseconds - 145_224_192), nil
	}
	return seconds*1_000_000_000 + nanoseconds, nil
}

func (root *Root) defaultExcluded(indexPath string) bool {
	if root.Path != string(filepath.Separator) {
		return false
	}
	switch indexPath {
	case "./dev", "./proc", "./run", "./sys", "./tmp":
		return true
	}
	return false
}

func displayPath(relative string) string {
	if relative == "" {
		return "."
	}
	return "./" + relative
}

func report(reporter Reporter, event Event) {
	if reporter != nil {
		reporter(event)
	}
}
