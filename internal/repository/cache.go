package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

const validationCacheVersion = 2

const maximumValidationCacheBytes = 4 << 20

type validationCache struct {
	Version    int               `json:"version"`
	CommitID   string            `json:"commit_id"`
	Sequence   int               `json:"sequence"`
	Transition TransitionKind    `json:"transition"`
	BlobIDs    map[string]string `json:"blob_ids"`
	Topology   []format.Mirror   `json:"topology"`
}

func loadValidationCache(path string) (validationCache, error) {
	if path == "" {
		return validationCache{}, os.ErrNotExist
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return validationCache{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > maximumValidationCacheBytes {
		return validationCache{}, fmt.Errorf("validation cache has invalid type, mode, or size")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumValidationCacheBytes+1))
	if err != nil {
		return validationCache{}, fmt.Errorf("read validation cache: %w", err)
	}
	if len(data) > maximumValidationCacheBytes {
		return validationCache{}, fmt.Errorf("validation cache exceeds %d bytes", maximumValidationCacheBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cache validationCache
	if err := decoder.Decode(&cache); err != nil {
		return validationCache{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return validationCache{}, fmt.Errorf("validation cache contains trailing JSON")
	}
	if err := validateValidationCache(cache); err != nil {
		return validationCache{}, err
	}
	return cache, nil
}

func validateValidationCache(cache validationCache) error {
	validTransition := cache.Sequence == 0 && cache.Transition == TransitionInvalid ||
		cache.Sequence > 0 && (cache.Transition == TransitionOrdinary || cache.Transition == TransitionRepair)
	if cache.Version != validationCacheVersion || !isGitOID(cache.CommitID) || cache.Sequence < 0 || !validTransition || len(cache.BlobIDs) != len(RequiredBlobNames) {
		return fmt.Errorf("invalid validation cache header")
	}
	for _, name := range RequiredBlobNames {
		if !isGitOID(cache.BlobIDs[name]) {
			return fmt.Errorf("validation cache lacks a valid blob ID for %q", name)
		}
	}
	if _, err := format.MarshalMirrors(cache.Topology); err != nil {
		return fmt.Errorf("invalid cached mirror topology: %w", err)
	}
	return nil
}

func writeValidationCache(path string, history *History) error {
	if path == "" {
		return nil
	}
	commit, err := history.Tip()
	if err != nil {
		return err
	}
	// Leave an older valid anchor in place when the permanent topology no
	// longer fits the deliberately small acceleration cache. History validation
	// remains correct without this cache.
	topology, fits, err := history.topologySnapshot(maximumValidationCacheBytes / 2)
	if err != nil {
		return err
	}
	if !fits {
		return nil
	}
	cache := validationCache{
		Version: validationCacheVersion, CommitID: commit.CommitID, Sequence: history.Len() - 1,
		Transition: commit.Transition, BlobIDs: commit.BlobIDs, Topology: topology,
	}
	if err := validateValidationCache(cache); err != nil {
		return err
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maximumValidationCacheBytes {
		return nil
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".validated-ancestor-")
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
	if _, err := file.Write(data); err != nil {
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
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func equalBlobIDs(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, id := range left {
		if right[name] != id {
			return false
		}
	}
	return true
}
