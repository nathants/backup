// Package securefs provides descriptor-confined operations on private
// operational workspaces.
package securefs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// RemoveTree removes a directory tree without following symlinks. The parent
// and every opened directory are retained by file descriptor, and a directory
// is unlinked only if its name still identifies the inode that was emptied.
func RemoveTree(root string) error {
	clean := filepath.Clean(root)
	parentPath, name := filepath.Dir(clean), filepath.Base(clean)
	if root == "" || name == "." || name == string(filepath.Separator) {
		return fmt.Errorf("invalid removal root %q", root)
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parentFD) }()
	rootFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(rootFD, &opened); err != nil {
		_ = unix.Close(rootFD)
		return err
	}
	removeErr := removeDirectoryContents(rootFD, clean)
	closeErr := unix.Close(rootFD)
	if removeErr != nil || closeErr != nil {
		return errors.Join(removeErr, closeErr)
	}
	if err := requireSameDirectory(parentFD, name, opened, clean); err != nil {
		return err
	}
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func removeDirectoryContents(directoryFD int, displayPath string) error {
	copyFD, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(copyFD), displayPath)
	for {
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			var stat unix.Stat_t
			if err := unix.Fstatat(directoryFD, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				_ = directory.Close()
				return err
			}
			entryPath := filepath.Join(displayPath, entry.Name())
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				childFD, err := unix.Openat(directoryFD, entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					_ = directory.Close()
					return err
				}
				var opened unix.Stat_t
				if err := unix.Fstat(childFD, &opened); err != nil {
					_ = unix.Close(childFD)
					_ = directory.Close()
					return err
				}
				childErr := removeDirectoryContents(childFD, entryPath)
				closeErr := unix.Close(childFD)
				if childErr != nil || closeErr != nil {
					_ = directory.Close()
					return errors.Join(childErr, closeErr)
				}
				if err := requireSameDirectory(directoryFD, entry.Name(), opened, entryPath); err != nil {
					_ = directory.Close()
					return err
				}
				if err := unix.Unlinkat(directoryFD, entry.Name(), unix.AT_REMOVEDIR); err != nil {
					_ = directory.Close()
					return err
				}
			case unix.S_IFREG, unix.S_IFLNK:
				if err := unix.Unlinkat(directoryFD, entry.Name(), 0); err != nil {
					_ = directory.Close()
					return err
				}
			default:
				_ = directory.Close()
				return fmt.Errorf("unexpected operational-state entry type at %q", entryPath)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = directory.Close()
			return readErr
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func requireSameDirectory(parentFD int, name string, opened unix.Stat_t, displayPath string) error {
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if current.Mode&unix.S_IFMT != unix.S_IFDIR || current.Dev != opened.Dev || current.Ino != opened.Ino {
		return fmt.Errorf("operational-state directory changed while removing %q", displayPath)
	}
	return nil
}
