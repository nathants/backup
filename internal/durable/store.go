package durable

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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

// Open opens or creates a store beneath an existing trusted parent. The caller
// must exclusively control the local namespace, including the parent's ancestors.
func Open(directory string) (*Store, error) {
	directory = filepath.Clean(directory)
	parentFD, err := unix.Open(filepath.Dir(directory), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parentFD) }()
	name := filepath.Base(directory)
	if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return nil, err
	}
	if err := unix.Fsync(fd); err != nil {
		return nil, err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return nil, err
	}
	opened = true
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
	temporary, err := store.createTemp()
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = unix.Unlinkat(store.fd, temporaryName, 0)
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
	if err := unix.Renameat(store.fd, temporaryName, store.fd, name); err != nil {
		return err
	}
	published = true
	return unix.Fsync(store.fd)
}

func (store *Store) createTemp() (*os.File, error) {
	for range 10 {
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return nil, fmt.Errorf("read temporary-name randomness: %w", err)
		}
		name := ".state-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(store.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), name), nil
	}
	return nil, fmt.Errorf("could not allocate a unique state temporary filename")
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

func validName(name string) error {
	if !namePattern.MatchString(name) || bytes.ContainsAny([]byte(name), "/\x00\r\n") {
		return fmt.Errorf("invalid durable state filename %q", name)
	}
	return nil
}
