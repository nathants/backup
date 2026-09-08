package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestWalkGitIgnoreWithoutRepository(t *testing.T) {
	for _, marker := range []string{"absent", "config-only", "empty-gitfile", "invalid-gitfile", "missing-head"} {
		t.Run(marker, func(t *testing.T) {
			home, source := t.TempDir(), t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", home)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "config"))
			write := func(base, name, value string) {
				t.Helper()
				path := filepath.Join(base, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(home, "config", "[core]\nexcludesFile = "+filepath.Join(home, "global")+"\n")
			write(home, "global", "*.global\n")
			switch marker {
			case "config-only":
				write(source, ".git/config", "\n")
				write(source, ".git/info/exclude", "*.local\n")
			case "empty-gitfile":
				write(source, ".git", "")
			case "invalid-gitfile":
				write(source, ".git", "not a gitfile\n")
			case "missing-head":
				gitFixture(t, source, "init", "-q")
				write(source, "tracked.tmp", "formerly tracked")
				gitFixture(t, source, "add", "tracked.tmp")
				if err := os.Remove(filepath.Join(source, ".git/HEAD")); err != nil {
					t.Fatal(err)
				}
				write(source, ".git/info/exclude", "*.local\n")
			}
			write(source, ".gitignore", "*.tmp\n!keep.tmp\n.git*\nblocked/\n")
			write(source, "nested/.gitignore", "!keep.tmp\n")
			for _, name := range []string{"keep", "drop.tmp", "keep.tmp", "drop.global", "drop.local", "nested/drop.tmp", "nested/keep.tmp", "blocked/untracked"} {
				write(source, name, "fixture")
			}
			root, err := OpenRoot(source)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			seen := map[string]bool{}
			var events []Event
			_, err = root.Walk(format.Ignore{}, func(event Event) { events = append(events, event) }, func(_ *File, row format.IndexEntry) error {
				seen[row.Path] = true
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"drop.tmp", "drop.global", "nested/drop.tmp", "blocked/untracked", "tracked.tmp"} {
				if seen["./"+name] {
					t.Errorf("ignored path included: %s", name)
				}
			}
			for _, name := range []string{"keep", "keep.tmp", "nested/keep.tmp"} {
				if !seen["./"+name] {
					t.Errorf("selected path missing: %s", name)
				}
			}
			if marker == "config-only" || marker == "missing-head" {
				if seen["./drop.local"] || !seen["./.git/info/exclude"] {
					t.Fatal("info/exclude rules or metadata preservation lost")
				}
			}
			if strings.HasSuffix(marker, "gitfile") && !seen["./.git"] {
				t.Fatal("invalid gitfile was omitted")
			}
			warnings := 0
			for _, event := range events {
				if event.Kind == "git-ignore-untracked-fallback" {
					warnings++
				}
			}
			if (marker != "absent") != (warnings == 1) {
				t.Fatalf("unexpected fallback diagnostics: %+v", events)
			}
		})
	}
}

func TestWalkGitIgnoreUnreadableRules(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	for _, rule := range []string{".gitignore", ".git/info/exclude", "global"} {
		t.Run(rule, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			path := filepath.Join(dir, rule)
			if rule == "global" {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("XDG_CONFIG_HOME", home)
				path = filepath.Join(home, "git/ignore")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("*\n"), 0000); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(path, 0600) }()
			root, err := OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error { return nil }); err == nil {
				t.Fatal("unreadable ignore file silently accepted")
			}
		})
	}
}

func TestWalkGitIgnoreFallbackWorkspaceIsPrivateAndRemoved(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			_, err = root.Walk(format.Ignore{}, nil, func(_ *File, row format.IndexEntry) error {
				if row.Path != "./keep" {
					t.Fatalf("matcher workspace entered the snapshot: %s", row.Path)
				}
				if fail {
					return os.ErrPermission
				}
				return nil
			})
			if (err != nil) != fail {
				t.Fatalf("walk error: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
				t.Fatalf("matcher workspace leaked: %v, %v", entries, err)
			}
		})
	}
}

func TestWalkGitIgnoreUnreadableAncestorRules(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	dir := t.TempDir()
	gitFixture(t, dir, "init", "-q")
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*\n"), 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(filepath.Join(dir, ".gitignore"), 0600) }()
	root, err := OpenRoot(subdir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error { return nil }); err == nil {
		t.Fatal("unreadable ancestor ignore was silently dropped")
	}
}

func TestWalkGitIgnoreUnreadableRelativeGitfileTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	base := t.TempDir()
	for _, name := range []string{"source", "metadata"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	metadata := filepath.Join(base, "metadata")
	gitFixture(t, metadata, "init", "--bare", "-q")
	if err := os.Chmod(filepath.Join(metadata, "HEAD"), 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(filepath.Join(metadata, "HEAD"), 0600) }()
	source := filepath.Join(base, "source")
	if err := os.WriteFile(filepath.Join(source, ".git"), []byte("gitdir: ../metadata\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error { return nil }); err == nil {
		t.Fatal("unreadable gitfile target became an untracked fallback")
	}
}

func TestWalkGitIgnoreUnavailableCommonDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	base := t.TempDir()
	repo, worktree := filepath.Join(base, "repo"), filepath.Join(base, "worktree")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, "init", "-q")
	gitFixture(t, repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "init")
	gitFixture(t, repo, "worktree", "add", "-qb", "linked", worktree)
	refs := filepath.Join(repo, ".git", "refs")
	if err := os.Chmod(refs, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(refs, 0700) }()
	root, err := OpenRoot(worktree)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error { return nil }); err == nil {
		t.Fatal("unreadable common directory became an untracked fallback")
	}
}
