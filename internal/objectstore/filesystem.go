package objectstore

import (
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
	"sync"

	"backup/internal/format"
	"backup/internal/securefs"
	"golang.org/x/sys/unix"
)

const filesystemMarker = ".backup-store"
const filesystemTempPrefix = ".backup-tmp-"

// Filesystem is an exclusively opened local store. Create-only is an application
// guarantee, not a security boundary against another process with disk access.
type Filesystem struct {
	reserveBytes               uint64
	mu                         sync.Mutex
	root                       *os.File
	directory, mount, identity string
	cleaned                    bool
	failurePoint               func(string) error
}

// InitializeFilesystem provisions an existing empty directory; ordinary opens
// never initialize a missing store. A failed initialization is preserved.
func InitializeFilesystem(directory, mount string) (string, error) {
	root, err := openFilesystemRoot(directory, mount)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return "", err
	}
	entries, err := root.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(entries) != 0 {
		return "", fmt.Errorf("filesystem store initialization requires an empty directory; preserve existing state")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	identity := "filesystem://" + hex.EncodeToString(random[:])
	name, file, err := filesystemTemp(int(root.Fd()))
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Unlinkat(int(root.Fd()), name, 0) }()
	_, writeErr := io.WriteString(file, "backup-filesystem-v1\n"+identity+"\n")
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return "", err
	}
	if err := unix.Renameat2(int(root.Fd()), name, int(root.Fd()), filesystemMarker, unix.RENAME_NOREPLACE); err != nil {
		return "", err
	}
	if err := errors.Join(root.Sync(), securefs.SyncParent(int(root.Fd()))); err != nil {
		return "", err
	}
	return identity, nil
}

func OpenFilesystem(directory, mount, identity string, reserveBytes uint64) (*Filesystem, error) {
	if _, err := format.MarshalMirrors([]format.Mirror{{Name: "local", Kind: format.MirrorFilesystem, S3URL: identity, Endpoint: "-", Region: "-"}}); err != nil {
		return nil, err
	}
	root, err := openFilesystemRoot(directory, mount)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("filesystem mirror is in use: %w", err)
	}
	store := &Filesystem{root: root, directory: directory, mount: mount, identity: identity, reserveBytes: reserveBytes}
	if err := store.check(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return store, nil
}

func (store *Filesystem) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

// All absolute components are opened without following symlinks.
func openAbsoluteDirectory(directory string) (*os.File, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\t\r\n") {
		return nil, fmt.Errorf("directory must be a canonical absolute path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if directory != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
			next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			_ = unix.Close(fd)
			if err != nil {
				return nil, err
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), directory), nil
}

func mountID(fd int) (uint64, error) {
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, fmt.Errorf("filesystem mount identity is unavailable")
	}
	return stat.Mnt_id, nil
}

func openFilesystemRoot(directory, mount string) (*os.File, error) {
	if directory == "/" {
		return nil, fmt.Errorf("filesystem store must not be the system root")
	}
	root, err := openAbsoluteDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("filesystem mirror unavailable: %w", err)
	}
	fail := func(err error) (*os.File, error) { _ = root.Close(); return nil, err }
	info, err := root.Stat()
	if err != nil {
		return fail(err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fail(fmt.Errorf("filesystem store must not be group/other writable"))
	}
	if mount != "" && mount != "-" {
		if mount == "/" || directory != mount && !strings.HasPrefix(directory, mount+"/") {
			return fail(fmt.Errorf("store must be beneath a non-root required mount"))
		}
		mounted, err := openAbsoluteDirectory(mount)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = mounted.Close() }()
		parent, err := unix.Openat(int(mounted.Fd()), "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = unix.Close(parent) }()
		rootID, e1 := mountID(int(root.Fd()))
		mountedID, e2 := mountID(int(mounted.Fd()))
		parentID, e3 := mountID(parent)
		if err := errors.Join(e1, e2, e3); err != nil {
			return fail(err)
		}
		if mountedID == parentID || rootID != mountedID {
			return fail(fmt.Errorf("required filesystem mount is absent or store is on a different mount"))
		}
	}
	return root, nil
}

func (store *Filesystem) check() error {
	if store.root == nil {
		return fmt.Errorf("filesystem store is closed")
	}
	current, err := openFilesystemRoot(store.directory, store.mount)
	if err != nil {
		return err
	}
	defer func() { _ = current.Close() }()
	expected, e1 := store.root.Stat()
	actual, e2 := current.Stat()
	if err := errors.Join(e1, e2); err != nil {
		return err
	}
	if !os.SameFile(expected, actual) {
		return fmt.Errorf("filesystem mirror directory changed; reopen explicitly")
	}
	file, err := regularAt(int(current.Fd()), filesystemMarker)
	if err != nil {
		return fmt.Errorf("filesystem store identity unavailable: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return err
	}
	if string(data) != "backup-filesystem-v1\n"+store.identity+"\n" {
		return fmt.Errorf("filesystem store identity does not match trusted configuration")
	}
	return nil
}

func regularAt(parent int, name string) (*os.File, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.Join(fmt.Errorf("store entry is not a readable regular file"), err)
	}
	return file, nil
}

func filesystemKeyHash(key string) (string, error) {
	parts := strings.Split(key, "/")
	var hash, canonical string
	var err error
	switch {
	case len(parts) == 3 && parts[0] == "objects":
		hash = parts[1]
		canonical, err = format.ObjectKey(hash, parts[2])
	case len(parts) == 4 && parts[0] == "metadata" && parts[1] == "parts":
		hash = parts[2]
		canonical, err = format.MetadataPartKey(format.ManifestPart{Hash: hash, ObjectID: parts[3]})
	case len(parts) == 5 && parts[0] == "metadata" && parts[1] == "manifests":
		hash = parts[3]
		canonical, err = format.MetadataManifestKey(parts[2], hash, parts[4])
	default:
		return "", fmt.Errorf("invalid filesystem object key")
	}
	if err != nil || canonical != key {
		return "", errors.Join(fmt.Errorf("invalid filesystem object key"), err)
	}
	return hash, nil
}

func (store *Filesystem) parent(key string, create bool) (int, string, error) {
	parts := strings.Split(key, "/")
	fd, err := unix.Openat(int(store.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		if create {
			err = unix.Mkdirat(fd, part, 0o700)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, "", err
			}
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == nil && create {
			err = unix.Fsync(fd)
		}
		_ = unix.Close(fd)
		if err != nil {
			if next >= 0 {
				_ = unix.Close(next)
			}
			return -1, "", err
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

func filesystemTemp(fd int) (string, *os.File, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, err
	}
	name := filesystemTempPrefix + hex.EncodeToString(random[:])
	fileFD, err := unix.Openat(fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", nil, err
	}
	return name, os.NewFile(uintptr(fileFD), name), nil
}

func (store *Filesystem) cleanupTemps() error {
	if store.cleaned {
		return nil
	}
	fd, err := unix.Openat(int(store.root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), "temps")
	defer func() { _ = dir.Close() }()
	for {
		entries, err := dir.ReadDir(256)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), filesystemTempPrefix) {
				continue
			}
			suffix := strings.TrimPrefix(entry.Name(), filesystemTempPrefix)
			if len(suffix) != 32 || strings.Trim(suffix, "0123456789abcdef") != "" {
				return fmt.Errorf("unexpected filesystem temporary name")
			}
			file, err := regularAt(fd, entry.Name())
			if err != nil {
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := store.root.Sync(); err != nil {
		return err
	}
	store.cleaned = true
	return nil
}

func (store *Filesystem) checkpoint(name string) error {
	if store.failurePoint != nil {
		return store.failurePoint(name)
	}
	return nil
}

type filesystemContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader filesystemContextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func (store *Filesystem) PutFile(ctx context.Context, key, filename string, expected Object) CreateResult {
	file, err := os.Open(filename)
	if err != nil {
		return CreateResult{Err: err}
	}
	defer func() { _ = file.Close() }()
	return store.PutOpenFile(ctx, key, file, expected)
}

func (store *Filesystem) PutOpenFile(ctx context.Context, key string, source *os.File, expected Object) (result CreateResult) {
	store.mu.Lock()
	defer store.mu.Unlock()
	fail := func(err error) CreateResult { return CreateResult{Err: err} }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := store.check(); err != nil {
		return fail(err)
	}
	if err := expected.validate(); err != nil {
		return fail(err)
	}
	hash, err := filesystemKeyHash(key)
	if err != nil {
		return fail(err)
	}
	if hash != expected.BLAKE2b {
		return fail(fmt.Errorf("key checksum disagrees with metadata"))
	}
	if source == nil {
		return fail(fmt.Errorf("source file is required"))
	}
	info, err := source.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || uint64(info.Size()) != expected.Size {
		return fail(fmt.Errorf("source size/type mismatch"))
	}
	// A retry must not need space for another copy of an existing object.
	// Existence is only a conflict; the caller must still audit the bytes.
	existingParent, existingLeaf, existingErr := store.parent(key, false)
	if existingErr == nil {
		var stat unix.Stat_t
		existingErr = unix.Fstatat(existingParent, existingLeaf, &stat, unix.AT_SYMLINK_NOFOLLOW)
		_ = unix.Close(existingParent)
		if existingErr == nil {
			return CreateResult{Disposition: CreateConflict, Err: unix.EEXIST}
		}
	}
	if !errors.Is(existingErr, unix.ENOENT) {
		return fail(existingErr)
	}
	if err := store.cleanupTemps(); err != nil {
		return fail(err)
	}
	if err := store.requireCapacity(expected.Size); err != nil {
		return fail(err)
	}
	name, file, err := filesystemTemp(int(store.root.Fd()))
	if err != nil {
		return fail(err)
	}
	defer func() {
		_ = file.Close()
		if err := unix.Unlinkat(int(store.root.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			result.Err = errors.Join(result.Err, err)
			result.Disposition = CreateFailed
		}
	}()
	limited := io.LimitReader(filesystemContextReader{ctx, source}, int64(expected.Size)+1)
	actual, err := HashReader(io.TeeReader(limited, file))
	if err != nil {
		return fail(err)
	}
	if actual != expected {
		return fail(fmt.Errorf("source object checksum/size mismatch"))
	}
	if err := store.checkpoint("written"); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := store.checkpoint("file-synced"); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return fail(err)
	}
	parent, leaf, err := store.parent(key, true)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = unix.Close(parent) }()
	if err := store.checkpoint("parents-synced"); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := store.check(); err != nil {
		return fail(err)
	}
	if err := unix.Renameat2(int(store.root.Fd()), name, parent, leaf, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return CreateResult{Disposition: CreateConflict, Err: err}
		}
		return fail(err)
	}
	if err := store.checkpoint("published"); err != nil {
		return CreateResult{Disposition: CreateAmbiguous, Err: err}
	}
	if err := errors.Join(unix.Fsync(parent), store.root.Sync()); err != nil {
		return CreateResult{Disposition: CreateAmbiguous, Err: err}
	}
	if err := store.checkpoint("directory-synced"); err != nil {
		return CreateResult{Disposition: CreateAmbiguous, Err: err}
	}
	return CreateResult{Disposition: CreateAcknowledged}
}

func (store *Filesystem) openObject(key string) (*os.File, error) {
	if _, err := filesystemKeyHash(key); err != nil {
		return nil, err
	}
	parent, leaf, err := store.parent(key, false)
	if err == nil {
		defer func() { _ = unix.Close(parent) }()
		var file *os.File
		file, err = regularAt(parent, leaf)
		if err == nil {
			return file, nil
		}
	}
	if errors.Is(err, unix.ENOENT) {
		if checkErr := store.check(); checkErr != nil {
			return nil, checkErr
		}
		return nil, fmt.Errorf("%w: %s", ErrMissing, key)
	}
	return nil, err
}

func (store *Filesystem) GetVerified(ctx context.Context, key string, expected Object, output io.Writer) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.getVerified(ctx, key, expected, output)
}
func (store *Filesystem) getVerified(ctx context.Context, key string, expected Object, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := store.check(); err != nil {
		return err
	}
	if output == nil {
		return fmt.Errorf("output writer is required")
	}
	if err := expected.validate(); err != nil {
		return err
	}
	hash, err := filesystemKeyHash(key)
	if err != nil {
		return err
	}
	if hash != expected.BLAKE2b {
		return fmt.Errorf("key checksum disagrees with metadata")
	}
	file, err := store.openObject(key)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	actual, err := HashReader(io.TeeReader(io.LimitReader(filesystemContextReader{ctx, file}, int64(expected.Size)+1), output))
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%w: filesystem object checksum/size mismatch", ErrCorrupt)
	}
	// Persist an existing object's bytes and directory entries before using this
	// audit as acknowledgement of a create whose response was lost.
	if err := file.Sync(); err != nil {
		return err
	}
	return store.syncParents(key)
}

func (store *Filesystem) Audit(ctx context.Context, key string, expected Object) error {
	return store.GetVerified(ctx, key, expected, io.Discard)
}

func (store *Filesystem) syncParents(key string) error {
	parent, _, err := store.parent(key, false)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	// Flush each containing entry through the opened descriptors.
	levels := len(strings.Split(key, "/"))
	for depth := 0; depth < levels; depth++ {
		if err := unix.Fsync(parent); err != nil {
			return err
		}
		if depth+1 == levels {
			return securefs.SyncParent(parent)
		}
		next, err := unix.Openat(parent, "..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		_ = unix.Close(parent)
		parent = next
	}
	return nil
}

func (store *Filesystem) GetManifest(ctx context.Context, key, expectedHash string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := store.check(); err != nil {
		return nil, err
	}
	hash, err := filesystemKeyHash(key)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(key, "metadata/manifests/") || hash != expectedHash {
		return nil, fmt.Errorf("invalid manifest key/hash")
	}
	file, err := store.openObject(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(filesystemContextReader{ctx, file}, maximumManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximumManifestBytes {
		return nil, fmt.Errorf("manifest exceeds size limit")
	}
	if HashBytes(data).BLAKE2b != expectedHash {
		return nil, fmt.Errorf("%w: filesystem manifest checksum mismatch", ErrCorrupt)
	}
	if err := errors.Join(file.Sync(), store.syncParents(key)); err != nil {
		return nil, err
	}
	return data, nil
}

func (store *Filesystem) List(ctx context.Context, prefix string) ([]string, error) {
	return store.ListLimited(ctx, prefix, maximumListedKeys)
}
func (store *Filesystem) ListLimited(ctx context.Context, prefix string, maximum int) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if maximum < 1 || maximum > maximumListedKeys {
		return nil, fmt.Errorf("invalid listing limit")
	}
	if _, err := (&Client{}).listPrefix(prefix); err != nil {
		return nil, err
	}
	if err := store.check(); err != nil {
		return nil, err
	}
	var keys []string
	visited := 0
	var walk func(int, string, int) error
	walk = func(fd int, path string, depth int) error {
		if depth > 4 {
			return fmt.Errorf("invalid filesystem object directory depth")
		}
		copyFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(copyFD), path)
		defer func() { _ = dir.Close() }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			entries, readErr := dir.ReadDir(256)
			for _, entry := range entries {
				key := path + entry.Name()
				if !strings.HasPrefix(key, prefix) && !strings.HasPrefix(prefix, key+"/") {
					continue
				}
				visited++
				if visited > maximum*5+16 {
					return fmt.Errorf("filesystem listing exceeds directory budget")
				}
				var stat unix.Stat_t
				if err := unix.Fstatat(fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				switch stat.Mode & unix.S_IFMT {
				case unix.S_IFDIR:
					child, err := unix.Openat(fd, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
					if err != nil {
						return err
					}
					err = walk(child, key+"/", depth+1)
					_ = unix.Close(child)
					if err != nil {
						return err
					}
				case unix.S_IFREG:
					if _, err := filesystemKeyHash(key); err != nil {
						return err
					}
					if strings.HasPrefix(key, prefix) {
						keys = append(keys, key)
						if len(keys) > maximum {
							return fmt.Errorf("filesystem listing exceeds %d keys", maximum)
						}
					}
				default:
					return fmt.Errorf("unexpected filesystem object type")
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
		}
	}
	if err := walk(int(store.root.Fd()), "", 0); err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

func (store *Filesystem) requireCapacity(size uint64) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(store.root.Fd()), &stat); err != nil {
		return err
	}
	if stat.Bsize <= 0 || stat.Bavail > ^uint64(0)/uint64(stat.Bsize) {
		return fmt.Errorf("invalid filesystem capacity")
	}
	available := stat.Bavail * uint64(stat.Bsize)
	if size > available || store.reserveBytes > available-size || stat.Ffree < 16 {
		return fmt.Errorf("filesystem mirror lacks space/inode reserve for %d bytes", size)
	}
	return nil
}
