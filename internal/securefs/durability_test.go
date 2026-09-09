package securefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyncParentUsesAnOpenedDirectory(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(child)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	if err := os.Rename(child, filepath.Join(root, "renamed")); err != nil {
		t.Fatal(err)
	}
	if err := SyncParent(int(directory.Fd())); err != nil {
		t.Fatalf("flush through retained descriptor: %v", err)
	}
	if err := SyncParent(-1); !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid descriptor failure lost: %v", err)
	}
	file, err := os.CreateTemp(root, "regular-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := SyncParent(int(file.Fd())); !errors.Is(err, unix.ENOTDIR) {
		t.Fatalf("regular-file descriptor accepted: %v", err)
	}
}
