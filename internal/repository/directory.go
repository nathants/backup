package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"backup/internal/securefs"
	"golang.org/x/sys/unix"
)

// Prepare missing trusted setup ancestors one at a time, persisting each before
// creating descendants. Existing parents are also flushed so a retry can finish
// an earlier mkdir whose containing-directory barrier failed.
func makeDurableParents(directory string) error {
	err := os.Mkdir(directory, 0o700)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(directory)
		if parent == directory {
			return err
		}
		if err := makeDurableParents(parent); err != nil {
			return err
		}
		err = os.Mkdir(directory, 0o700)
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	// Ancestors are trusted local paths and retain MkdirAll's alias semantics;
	// the metadata-directory leaf itself is opened separately with NOFOLLOW.
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open setup parent for fsync: %w", err)
	}
	syncErr := unix.Fsync(fd)
	if syncErr == nil {
		syncErr = securefs.SyncParent(fd)
	}
	return errors.Join(syncErr, unix.Close(fd))
}
