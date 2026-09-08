package durable

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const maximumStateBytes = 8 << 20

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Store struct {
	directory string
	fd        int
}

func Open(directory string) (*Store, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return &Store{directory: directory, fd: fd}, nil
}

func (store *Store) Close() error {
	if store == nil || store.fd < 0 {
		return nil
	}
	err := unix.Close(store.fd)
	store.fd = -1
	return err
}

func (store *Store) Directory() string { return store.directory }

func (store *Store) Write(name string, value any) error {
	if err := validName(name); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maximumStateBytes {
		return fmt.Errorf("durable state exceeds %d bytes", maximumStateBytes)
	}
	temporary, err := os.CreateTemp(store.directory, ".state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(store.directory, name)); err != nil {
		return err
	}
	published = true
	return unix.Fsync(store.fd)
}

func (store *Store) Read(name string, destination any) error {
	if err := validName(name); err != nil {
		return err
	}
	fd, err := unix.Openat(store.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumStateBytes {
		return fmt.Errorf("durable state file has invalid type or size")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("durable state contains trailing JSON")
	}
	return nil
}

func (store *Store) Reset() error {
	copyFD, err := unix.Dup(store.fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(copyFD), store.directory)
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(store.fd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG, unix.S_IFLNK:
			if err := unix.Unlinkat(store.fd, entry.Name(), 0); err != nil {
				return err
			}
		case unix.S_IFDIR:
			childFD, err := unix.Openat(store.fd, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			if err := removeDirectoryContents(childFD); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			if err := unix.Close(childFD); err != nil {
				return err
			}
			if err := unix.Unlinkat(store.fd, entry.Name(), unix.AT_REMOVEDIR); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected durable state entry type %q", entry.Name())
		}
	}
	return unix.Fsync(store.fd)
}

func removeDirectoryContents(directoryFD int) error {
	copyFD, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(copyFD), "durable-subdirectory")
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG, unix.S_IFLNK:
			if err := unix.Unlinkat(directoryFD, entry.Name(), 0); err != nil {
				return err
			}
		case unix.S_IFDIR:
			childFD, err := unix.Openat(directoryFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			if err := removeDirectoryContents(childFD); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			if err := unix.Close(childFD); err != nil {
				return err
			}
			if err := unix.Unlinkat(directoryFD, entry.Name(), unix.AT_REMOVEDIR); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected durable state entry type %q", entry.Name())
		}
	}
	return unix.Fsync(directoryFD)
}

func validName(name string) error {
	if !namePattern.MatchString(name) || bytes.ContainsAny([]byte(name), "/\x00\r\n") {
		return fmt.Errorf("invalid durable state filename %q", name)
	}
	return nil
}
