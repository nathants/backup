package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestWalkGitIgnoreGitfileAndLiteralNames(t *testing.T) {
	base := t.TempDir()
	repo, worktree := filepath.Join(base, "main"), filepath.Join(base, "linked")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, "init", "-q")
	gitFixture(t, repo, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "init")
	gitFixture(t, repo, "worktree", "add", "-qb", "linked", worktree)
	if err := os.WriteFile(filepath.Join(worktree, ".gitignore"), []byte("*.tmp\n.git/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"drop.tmp", "colon:name", ":(top)literal", "[a]*", "space name"} {
		if err := os.WriteFile(filepath.Join(worktree, name), []byte("file"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Inherited Git environment must not redirect the scanner or enable hooks.
	t.Setenv("GIT_DIR", "/does/not/exist")
	t.Setenv("GIT_WORK_TREE", "/does/not/exist")
	t.Setenv("GIT_LITERAL_PATHSPECS", "1")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
	t.Setenv("GIT_CONFIG_VALUE_0", "/does/not/exist")
	root, err := OpenRoot(worktree)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	seen := map[string]bool{}
	_, err = root.Walk(format.Ignore{}, nil, func(_ *File, row format.IndexEntry) error { seen[row.Path] = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if seen["./drop.tmp"] {
		t.Fatal("ignored file included")
	}
	for _, name := range []string{".git", "colon:name", ":(top)literal", "[a]*", "space name"} {
		if !seen["./"+name] {
			t.Errorf("literal file omitted: %s", name)
		}
	}
}

func TestWalkGitIgnoreFailuresAndCleanup(t *testing.T) {
	for _, kind := range []string{"corrupt-marker", "marker-symlink", "bad-config", "oversized-pattern", "callback-error"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			gitFixture(t, dir, "init", "-q")
			switch kind {
			case "corrupt-marker":
				if err := os.Remove(filepath.Join(dir, ".git", "HEAD")); err != nil {
					t.Fatal(err)
				}
			case "marker-symlink":
				if err := os.Rename(filepath.Join(dir, ".git"), filepath.Join(dir, "actual")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("actual", filepath.Join(dir, ".git")); err != nil {
					t.Fatal(err)
				}
			case "bad-config":
				if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("invalid config"), 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized-pattern":
				if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(strings.Repeat("*", 70<<10)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			_, err = root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error {
				if kind == "callback-error" {
					return os.ErrPermission
				}
				return nil
			})
			if err == nil {
				t.Fatal("failed Git query/visitor was accepted")
			}
		})
	}
}

func TestWalkGitIgnorePrunesBeforeReading(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	dir := t.TempDir()
	gitFixture(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("unreadable/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "unreadable")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(blocked, 0700) }()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var events []Event
	result, err := root.Walk(format.Ignore{}, func(event Event) { events = append(events, event) }, func(_ *File, _ format.IndexEntry) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.SkippedGitIgnored != 1 || len(events) != 1 || events[0].Path != "./unreadable" || events[0].Kind != EventGitIgnored {
		t.Fatalf("ignored directory diagnostic: %+v %+v", result, events)
	}
}

func TestWalkGitIgnoreSubmodule(t *testing.T) {
	base := t.TempDir()
	child, parent := filepath.Join(base, "source"), filepath.Join(base, "parent")
	for _, dir := range []string{child, parent} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		gitFixture(t, dir, "init", "-q")
		gitFixture(t, dir, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "init")
	}
	gitFixture(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q", child, "sub")
	for _, item := range []struct{ name, text string }{{".gitignore", "*.tmp\n"}, {"keep", "keep"}, {"drop.tmp", "drop"}} {
		if err := os.WriteFile(filepath.Join(parent, "sub", item.name), []byte(item.text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	seen := map[string]bool{}
	_, err = root.Walk(format.Ignore{}, nil, func(_ *File, row format.IndexEntry) error { seen[row.Path] = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !seen["./sub/keep"] || seen["./sub/drop.tmp"] {
		t.Fatal("submodule ignores not applied")
	}
}

func TestWalkOwnRepositoryDoesNotInspectOuterRepository(t *testing.T) {
	outer := t.TempDir()
	if err := os.Mkdir(filepath.Join(outer, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, inner, "init", "-q")
	root, err := OpenRoot(inner)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Walk(format.Ignore{}, nil, func(_ *File, _ format.IndexEntry) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
