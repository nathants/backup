package filesystem

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestWalkReusingDoesNotOpenKnownContents(t *testing.T) {
	path := t.TempDir()
	mustWrite(t, filepath.Join(path, "known"), []byte("old"), 0600)
	root, err := OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var cached format.IndexEntry
	if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, e format.IndexEntry) error { cached = e; return nil }); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(path, "known"), []byte("new contents and size"), 0600)
	mustWrite(t, filepath.Join(path, "new"), []byte("new"), 0600)
	var opened []string
	root.scanOpened = func(path string) error {
		opened = append(opened, path)
		if path == "./known" {
			return fmt.Errorf("cached content was opened")
		}
		return nil
	}
	var observed format.IndexEntry
	result, err := root.WalkReusing(format.Ignore{}, nil, func(path string) (*format.IndexEntry, error) {
		if path == cached.Path {
			return &cached, nil
		}
		return nil, nil
	}, func(_ *File, e format.IndexEntry) error {
		if e.Path == cached.Path {
			observed = e
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.HashedFiles != 1 || result.ReusedFiles != 1 || observed != cached || len(opened) != 1 || opened[0] != "./new" {
		t.Fatalf("reuse: %+v observed=%+v opened=%v", result, observed, opened)
	}
	// The ordinary Walk path must never inherit the cache.
	if _, err := root.Walk(format.Ignore{}, nil, func(*File, format.IndexEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "cached content was opened") {
		t.Fatalf("ordinary scan skipped hashing: %v", err)
	}
}

func TestWalkReusingAppliesCurrentIgnoreBeforeLookup(t *testing.T) {
	path := t.TempDir()
	mustMkdir(t, filepath.Join(path, "excluded"))
	mustWrite(t, filepath.Join(path, "excluded", "known"), []byte("contents"), 0600)
	mustWrite(t, filepath.Join(path, "git-ignored"), []byte("contents"), 0600)
	mustWrite(t, filepath.Join(path, ".gitignore"), []byte("git-ignored\n"), 0600)
	root, err := OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ignore, err := format.ParseIgnore(strings.NewReader("^\\./excluded$\n"), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	result, err := root.WalkReusing(ignore, nil, func(path string) (*format.IndexEntry, error) {
		if path != "./.gitignore" {
			t.Fatalf("looked up ignored path: %s", path)
		}
		return nil, nil
	}, func(*File, format.IndexEntry) error { return nil })
	if err != nil || result.Entries != 1 || result.SkippedGitIgnored != 1 {
		t.Fatalf("current ignore policy: %+v %v", result, err)
	}
}
