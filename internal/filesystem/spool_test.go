package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolUsesRetainedDescriptorsAndRemovesPrivateChild(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := PrepareSpool(parent, "repository-spool")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(parent, "repository-spool"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("spool mode=%v", info.Mode())
	}
	moved := filepath.Join(base, "moved-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	file, err := spool.Create("./file", 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.File.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := spool.CloseAndRemove(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(moved)
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool cleanup entries=%v err=%v", entries, err)
	}
}

func TestSpoolRejectsUnexpectedStaleEntry(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "repository-spool")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	name := spoolFilePrefix + strings.Repeat("0", spoolRandomBytes*2)
	if err := os.Symlink("outside", filepath.Join(child, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareSpool(parent, "repository-spool"); err == nil || !strings.Contains(err.Error(), "unexpected type") {
		t.Fatalf("unexpected stale symlink was accepted: %v", err)
	}
}

func TestCheckSpoolCapacity(t *testing.T) {
	if err := checkSpoolCapacity(100, 20, 120, spoolInodeHeadroom+1); err != nil {
		t.Fatalf("exact capacity rejected: %v", err)
	}
	if err := checkSpoolCapacity(100, 21, 120, spoolInodeHeadroom+1); err == nil || !strings.Contains(err.Error(), "only 120 bytes") {
		t.Fatalf("insufficient bytes accepted: %v", err)
	}
	if err := checkSpoolCapacity(^uint64(0), 1, ^uint64(0), spoolInodeHeadroom+1); err == nil || !strings.Contains(err.Error(), "not representable") {
		t.Fatalf("overflowing requirement accepted: %v", err)
	}
	if err := checkSpoolCapacity(1, 1, 2, spoolInodeHeadroom); err == nil || !strings.Contains(err.Error(), "free inodes") {
		t.Fatalf("inode headroom violation accepted: %v", err)
	}
}
