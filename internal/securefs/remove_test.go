package securefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRemoveTreeRemovesNestedTreeWithoutFollowingSymlinks(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "tree")
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker")
	if err := os.WriteFile(marker, []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTree(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("tree still exists: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "retained" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}
}

func TestDescriptorRemovalStaysOnOpenedDirectoryAfterNameSwap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	moved := filepath.Join(parent, "opened-state")
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "inside"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	if err := removeDirectoryContents(fd, root); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "outside" {
		t.Fatalf("swapped symlink target changed: %q %v", data, err)
	}
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 0 {
		t.Fatalf("opened directory was not emptied: %#v %v", entries, err)
	}
}

func TestRemoveTreeRejectsChangedRootIdentity(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "state")
	outside := t.TempDir()
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTree(root); err == nil || !(strings.Contains(err.Error(), "not a directory") || strings.Contains(err.Error(), "symbolic link") || strings.Contains(err.Error(), "too many levels")) {
		t.Fatalf("symlink removal root was accepted: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("symlink target was removed: %v", err)
	}
}
