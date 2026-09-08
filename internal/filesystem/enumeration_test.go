package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestWalkReopensDirectoryForEveryEnumeration(t *testing.T) {
	path := t.TempDir()
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(path, fmt.Sprintf("file-%03d", i)), []byte("content"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for pass := range 3 {
		if pass == 1 {
			if err := os.Remove(filepath.Join(path, "file-000")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "new"), []byte("new content"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		seen := map[string]bool{}
		result, err := root.Walk(format.Ignore{}, nil, func(_ *File, entry format.IndexEntry) error {
			if seen[entry.Path] {
				return fmt.Errorf("duplicate entry %s", entry.Path)
			}
			seen[entry.Path] = true
			return nil
		})
		if err != nil || result.Entries != 300 || len(seen) != 300 {
			t.Fatalf("pass %d: entries=%d seen=%d err=%v", pass, result.Entries, len(seen), err)
		}
		if pass > 0 && (!seen["./new"] || seen["./file-000"]) {
			t.Fatalf("pass %d used stale entries", pass)
		}
	}
}

func TestSpoolCleanupReenumeratesAfterPreparation(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "spool")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(child, spoolFilePrefix+strings.Repeat("0", spoolRandomBytes*2))
	if err := os.WriteFile(seed, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := PrepareSpool(parent, "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.CloseAndRemove() })
	if _, err := os.Lstat(seed); !os.IsNotExist(err) {
		t.Fatalf("preparation did not remove the stale seed: %v", err)
	}
	for range 300 {
		file, err := spool.Create("./source", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		// Leave the child for directory cleanup, as after interrupted capture.
		if err := file.File.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.CloseAndRemove(); err != nil {
		t.Fatalf("second enumeration failed to clean remaining files: %v", err)
	}
	if _, err := os.Lstat(child); !os.IsNotExist(err) {
		t.Fatalf("private spool directory remains: %v", err)
	}
}

func TestSpoolCleanupReenumeratesAndRejectsNewUnsafeEntry(t *testing.T) {
	parent := t.TempDir()
	spool, err := PrepareSpool(parent, "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.CloseAndRemove() })
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := spoolFilePrefix + strings.Repeat("0", spoolRandomBytes*2)
	if err := os.Symlink(outside, filepath.Join(spool.Path(), name)); err != nil {
		t.Fatal(err)
	}
	if err := spool.CloseAndRemove(); err == nil || !strings.Contains(err.Error(), "unexpected type or owner") {
		t.Fatalf("new symlink not rejected at the type check: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("outside content changed: %q, %v", data, err)
	}
}
