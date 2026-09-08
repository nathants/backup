package filesystem

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func gitFixture(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

func TestWalkGitIgnore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "config"))
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, "global-ignore"), "*.global\n")
	write(filepath.Join(home, "config"), "[core]\nexcludesFile = "+filepath.Join(home, "global-ignore")+"\n")
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, "init", "-q")
	for _, name := range []string{"ignored/tracked", "tracked.tmp"} {
		write(filepath.Join(repo, name), name)
	}
	gitFixture(t, repo, "add", "ignored/tracked", "tracked.tmp")
	write(filepath.Join(repo, ".gitignore"), "*.tmp\nignored/\n!keep.tmp\n")
	write(filepath.Join(repo, ".git", "info", "exclude"), "*.local\n")
	for _, name := range []string{"new.txt", "drop.tmp", "keep.tmp", "drop.global", "drop.local", "ignored/untracked", "nested/drop.tmp", "nested/keep.tmp"} {
		write(filepath.Join(repo, name), name)
	}
	write(filepath.Join(repo, "nested", ".gitignore"), "!keep.tmp\n")
	write(filepath.Join(base, "outside.tmp"), "outside")
	// Independent nested repositories get their own ignore rules.
	nested := filepath.Join(repo, "child")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, nested, "init", "-q")
	write(filepath.Join(nested, "keep.tmp"), "nested repository")
	write(filepath.Join(nested, ".gitignore"), "*.child\n")
	write(filepath.Join(nested, "drop.child"), "ignored")
	root, err := OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	seen := map[string]bool{}
	_, err = root.Walk(format.Ignore{}, nil, func(_ *File, row format.IndexEntry) error { seen[row.Path] = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"outside.tmp", "repo/new.txt", "repo/keep.tmp", "repo/tracked.tmp", "repo/ignored/tracked", "repo/nested/keep.tmp", "repo/child/keep.tmp", "repo/.git/config"} {
		if !seen["./"+name] {
			t.Errorf("missing %s", name)
		}
	}
	for _, name := range []string{"repo/drop.tmp", "repo/drop.global", "repo/drop.local", "repo/ignored/untracked", "repo/nested/drop.tmp", "repo/child/drop.child"} {
		if seen["./"+name] {
			t.Errorf("Git-ignored file was backed up: %s", name)
		}
	}
	// The backup root can itself be inside a worktree.
	subroot, err := OpenRoot(filepath.Join(repo, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = subroot.Close() }()
	seen = map[string]bool{}
	_, err = subroot.Walk(format.Ignore{}, nil, func(_ *File, row format.IndexEntry) error { seen[row.Path] = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if seen["./drop.tmp"] || !seen["./keep.tmp"] {
		t.Fatal("root inside a repository lost parent ignore rules")
	}
	// Backup's explicit exclusions still take precedence over tracked status.
	ignore, err := format.ParseIgnore(strings.NewReader("tracked\n"), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.Walk(ignore, nil, func(_ *File, row format.IndexEntry) error {
		if strings.Contains(row.Path, "tracked") {
			t.Errorf("explicit exclusion bypassed: %s", row.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
