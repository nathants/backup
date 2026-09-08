package repository

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestValidatorAcceptsLinearSHA256History(t *testing.T) {
	repo := initTestRepo(t, "sha256")
	writeBlobs(t, repo, validGenesisBlobs(t))
	runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")

	validator := Validator{Repo: repo, Limits: format.DefaultLimits()}
	history, err := validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if history.Len() != 1 {
		t.Fatalf("history length %d", history.Len())
	}
	first, err := history.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.State.ValidateGenesis(); err != nil {
		t.Fatal(err)
	}
	if len(first.CommitID) != 64 {
		t.Fatalf("unexpected SHA-256 commit %q", first.CommitID)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}

	blobs := validGenesisBlobs(t)
	blobs["ignore"] = []byte("^\\./tmp(?:/|$)\n")
	writeBlobs(t, repo, blobs)
	runGitTest(t, repo, "add", "--", "ignore")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "config")
	history, err = validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	if history.Len() != 2 {
		t.Fatalf("second history: len=%d", history.Len())
	}
	second, err := history.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if second.Transition != TransitionOrdinary {
		t.Fatalf("transition=%v", second.Transition)
	}
}

func TestValidatorCacheFallsBackSafelyAndValidatesDescendants(t *testing.T) {
	repo := initTestRepo(t, "sha256")
	writeBlobs(t, repo, validGenesisBlobs(t))
	runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")
	cachePath := filepath.Join(t.TempDir(), "validated.json")
	validator := Validator{Repo: repo, Limits: format.DefaultLimits(), CachePath: cachePath}
	initial, err := validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(cachePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode=%v err=%v", info, err)
	}

	if err := os.WriteFile(cachePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "ignore"), []byte("^\\./tmp$\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, repo, "add", "--", "ignore")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "valid descendant")
	history, err := validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	if history.Len() != 2 {
		t.Fatalf("fallback validation history=%d", history.Len())
	}
	if _, err := loadValidationCache(cachePath); err != nil {
		t.Fatalf("fallback did not repair cache: %v", err)
	}

	if err := os.WriteFile(filepath.Join(repo, "FORMAT"), []byte("invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, repo, "add", "--", "FORMAT")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "invalid descendant")
	if _, err := validator.ValidateHistory("HEAD"); err == nil {
		t.Fatal("cached validation accepted an invalid descendant")
	}
}

func TestValidatorRejectsSHA1Repository(t *testing.T) {
	repo := initTestRepo(t, "sha1")
	validator := Validator{Repo: repo, Limits: format.DefaultLimits()}
	if _, err := validator.ValidateHistory("HEAD"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("SHA-1 repo was accepted: %v", err)
	}
}

func TestValidatorRejectsExtraPathAndNonRegularMode(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, repo string)
	}{
		{"extra path", func(t *testing.T, repo string) {
			if err := os.WriteFile(filepath.Join(repo, "extra"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			runGitTest(t, repo, "add", "--", "extra")
		}},
		{"executable mode", func(t *testing.T, repo string) {
			if err := os.Chmod(filepath.Join(repo, "FORMAT"), 0o755); err != nil {
				t.Fatal(err)
			}
			runGitTest(t, repo, "add", "--", "FORMAT")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := initTestRepo(t, "sha256")
			writeBlobs(t, repo, validGenesisBlobs(t))
			runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
			runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")
			test.mutate(t, repo)
			runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "bad")
			validator := Validator{Repo: repo, Limits: format.DefaultLimits()}
			if _, err := validator.ValidateHistory("HEAD"); err == nil {
				t.Fatal("malicious tree was accepted")
			}
		})
	}
}

func TestValidatorRejectsMergeHistory(t *testing.T) {
	repo := initTestRepo(t, "sha256")
	writeBlobs(t, repo, validGenesisBlobs(t))
	runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")
	parent := strings.TrimSpace(runGitTest(t, repo, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(runGitTest(t, repo, "rev-parse", "HEAD^{tree}"))
	orphanCommand := exec.Command("git", "-C", repo, "commit-tree", tree)
	orphanCommand.Env = append(os.Environ(), "GIT_AUTHOR_NAME=backup", "GIT_AUTHOR_EMAIL=backup@invalid", "GIT_COMMITTER_NAME=backup", "GIT_COMMITTER_EMAIL=backup@invalid")
	orphanCommand.Stdin = strings.NewReader("orphan\n")
	orphanOutput, err := orphanCommand.Output()
	if err != nil {
		t.Fatalf("orphan commit-tree: %v", err)
	}
	orphan := strings.TrimSpace(string(orphanOutput))
	command := exec.Command("git", "-C", repo, "commit-tree", tree, "-p", parent, "-p", orphan)
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=backup", "GIT_AUTHOR_EMAIL=backup@invalid", "GIT_COMMITTER_NAME=backup", "GIT_COMMITTER_EMAIL=backup@invalid")
	command.Stdin = strings.NewReader("merge\n")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("commit-tree: %v", err)
	}
	merge := strings.TrimSpace(string(output))
	validator := Validator{Repo: repo, Limits: format.DefaultLimits()}
	if _, err := validator.validateCommit(merge); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("merge was accepted: %v", err)
	}
}

func TestValidatorIgnoresHostileGitEnvironment(t *testing.T) {
	repo := t.TempDir()
	runGitTest(t, repo, "init", "--object-format=sha256", "--initial-branch=main")
	writeBlobs(t, repo, validGenesisBlobs(t))
	runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")
	tip := strings.TrimSpace(runGitTest(t, repo, "rev-parse", "HEAD"))
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "attacker.git"))
	t.Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(t.TempDir(), "attacker-objects"))
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", filepath.Join(t.TempDir(), "attacker-hooks"))
	hostileHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostileHome, ".gitconfig"), []byte("this is not valid git config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", hostileHome)
	history, err := (Validator{Repo: repo, Limits: format.DefaultLimits()}).ValidateHistory(tip)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	validatedTip, err := history.Tip()
	if err != nil || history.Len() != 1 || validatedTip.CommitID != tip {
		t.Fatalf("hostile process Git environment affected validation: count=%d tip=%#v err=%v", history.Len(), validatedTip, err)
	}
}

func TestValidatorInspectsDeclaredBlobSizeBeforeReading(t *testing.T) {
	repo := initTestRepo(t, "sha256")
	blobs := validGenesisBlobs(t)
	blobs["ignore"] = bytes.Repeat([]byte("x"), 1024)
	writeBlobs(t, repo, blobs)
	runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
	runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "genesis")
	limits := format.DefaultLimits()
	limits.MaxFileBytes = 512
	limits.MaxLineBytes = 256
	limits.MaxFieldBytes = 128
	validator := Validator{Repo: repo, Limits: limits}
	if _, err := validator.ValidateHistory("HEAD"); err == nil || !strings.Contains(err.Error(), "declared size") {
		t.Fatalf("oversized blob was read/accepted: %v", err)
	}
}

func initTestRepo(t *testing.T, objectFormat string) string {
	t.Helper()
	repo := t.TempDir()
	runGitTest(t, "", "init", "--object-format="+objectFormat, "--initial-branch=main", repo)
	return repo
}

func writeBlobs(t *testing.T, repo string, blobs map[string][]byte) {
	t.Helper()
	for name, data := range blobs {
		if err := os.WriteFile(filepath.Join(repo, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func runGitTest(t *testing.T, repo string, arguments ...string) string {
	t.Helper()
	args := append([]string{}, arguments...)
	if repo != "" {
		args = append([]string{"-C", repo}, args...)
	}
	command := exec.Command("git", args...)
	command.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}
