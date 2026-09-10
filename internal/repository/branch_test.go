package repository

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBranchSetupRejectsBeforeMutation(t *testing.T) {
	for _, branch := range []string{"main.lock", "archive.lock/home", "main.", "archive/.hidden", "archive//home", "archive/../home", "HEAD", "-main", "@{-1}", "main\x00other"} {
		t.Run(branch, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "metadata")
			if _, err := Initialize(directory, "/unused-remote.git", branch); err == nil {
				t.Error("initialized an invalid branch")
			}
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("invalid branch created metadata state: %v", err)
			}
			directory = filepath.Join(t.TempDir(), "metadata")
			repo, err := InitializeLocal(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.BindInitialRemote("/unused-remote.git", branch); err == nil {
				t.Error("bound an invalid branch")
			}
			remotes, err := repo.run(nil, 1024, "remote")
			if err != nil || len(remotes) != 0 {
				t.Errorf("invalid branch added origin: %q %v", remotes, err)
			}
			head, err := repo.run(nil, 1024, "symbolic-ref", "HEAD")
			if err != nil || strings.TrimSpace(string(head)) != "refs/heads/main" {
				t.Errorf("invalid branch changed HEAD: %q %v", head, err)
			}
		})
	}
}

func TestBranchSetupAcceptsSlashNames(t *testing.T) {
	for _, branch := range []string{"main", "archive/home", "archive/HEAD", "archive/-home", "archive/v1.0"} {
		t.Run(branch, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "metadata")
			if _, err := Initialize(directory, "/unused-remote.git", branch); err != nil {
				t.Fatalf("initialize valid branch: %v", err)
			}
			repo, err := InitializeLocal(filepath.Join(t.TempDir(), "metadata"))
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.BindInitialRemote("/unused-remote.git", branch); err != nil {
				t.Fatalf("bind valid branch: %v", err)
			}
			head, err := repo.run(nil, 1024, "symbolic-ref", "HEAD")
			if err != nil || string(head) != "refs/heads/"+branch+"\n" {
				t.Fatalf("branch changed during binding: %q %v", head, err)
			}
		})
	}
}

func TestBranchValidationRejectsCheckoutExpressions(t *testing.T) {
	directory := t.TempDir()
	runGitTest(t, directory, "init", "-q", "-b", "main")
	runGitTest(t, directory, "-c", "user.name=Test", "-c", "user.email=test@invalid", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "base")
	runGitTest(t, directory, "checkout", "-qb", "other")
	t.Chdir(directory)
	if got := runGitTest(t, directory, "check-ref-format", "--branch", "@{-1}"); got != "main\n" {
		t.Fatalf("checkout-expression control did not expand: %q", got)
	}
	if err := ValidateBranch("@{-1}"); err == nil || !strings.Contains(err.Error(), "literal branch") {
		t.Fatalf("accepted contextual branch expansion: %v", err)
	}
}
