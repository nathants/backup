package repository

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyCommitKeepsGitIndexAtAcceptedRevision(t *testing.T) {
	repo, err := InitializeLocal(filepath.Join(t.TempDir(), "metadata"))
	if err != nil {
		t.Fatal(err)
	}
	blobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", blobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ApplyCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, "")

	if err := os.WriteFile(filepath.Join(repo.Directory, "ignore"), []byte("staged-only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, " M ignore\n")
	if _, err := repo.RunGit(nil, 1024, "add", "--", "ignore"); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, "M  ignore\n")
	changed := cloneBlobs(blobs)
	changed["ignore"] = []byte("candidate-only\n")
	changed[".publickeys"] = []byte(strings.TrimSpace(string(blobs[".publickeys"])) + ":" + strings.Repeat("01", 32) + "\n")
	child, err := repo.CreateCommit(genesis, changed, "configuration update")
	if err != nil {
		t.Fatal(err)
	}
	// Candidate construction must neither consume nor replace Git's index.
	assertGitStatus(t, repo, "M  ignore\n")
	if err := repo.ApplyCommit(child, genesis); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, "")
	for _, name := range []string{"ignore", ".publickeys"} {
		indexed, err := repo.RunGit(nil, 1024, "show", ":"+name)
		if err != nil || string(indexed) != string(changed[name]) {
			t.Fatalf("indexed %s differs from accepted candidate: %q %v", name, indexed, err)
		}
	}

	if err := repo.ApplyCommit(genesis, child); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, "")
	if err := repo.ApplyCommit("", genesis); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, "")
}

func TestResetIndexPreservesUnstagedWorktreeEdits(t *testing.T) {
	repo, err := InitializeLocal(filepath.Join(t.TempDir(), "metadata"))
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := repo.CreateCommit("", validGenesisBlobs(t), "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ApplyCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo.Directory, "ignore")
	edited := "local edit\n"
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(repo.Directory, ".git", "index")); err != nil {
		t.Fatal(err)
	}
	if err := repo.ResetIndex(genesis); err != nil {
		t.Fatal(err)
	}
	assertGitStatus(t, repo, " M ignore\n")
	if data, err := os.ReadFile(path); err != nil || string(data) != edited {
		t.Fatalf("index reconstruction changed the worktree: %q %v", data, err)
	}
	if head, err := repo.Head(); err != nil || head != genesis {
		t.Fatalf("index reconstruction changed HEAD: %s %v", head, err)
	}
}

func TestMaterializationRecoversGitIndex(t *testing.T) {
	for _, point := range []string{"materialization-ref-updated", "materialization-index-updated", "index-lock"} {
		t.Run(point, func(t *testing.T) {
			repo, err := InitializeLocal(filepath.Join(t.TempDir(), "metadata"))
			if err != nil {
				t.Fatal(err)
			}
			blobs := validGenesisBlobs(t)
			genesis, err := repo.CreateCommit("", blobs, "genesis")
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.ApplyCommit(genesis, ""); err != nil {
				t.Fatal(err)
			}
			blobs["ignore"] = []byte("changed\n")
			child, err := repo.CreateCommit(genesis, blobs, "configuration update")
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(repo.Directory, ".git", "index.lock")
			if point == "index-lock" {
				if err := os.WriteFile(lock, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				repo.MaterializationFailurePoint = func(observed string) error {
					if observed == point {
						return errors.New("interrupted materialization")
					}
					return nil
				}
			}
			if err := repo.ApplyCommit(child, genesis); err == nil {
				t.Fatal("materialization did not report the interruption or index write failure")
			}
			if point == "index-lock" {
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err := OpenLocal(repo.Directory, "main")
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.RecoverMaterialization(); err != nil {
				t.Fatal(err)
			}
			if head, err := reopened.Head(); err != nil || head != child {
				t.Fatalf("recovery head=%s err=%v; want %s", head, err, child)
			}
			assertGitStatus(t, reopened, "")
			if _, exists, err := reopened.readMaterializationIntent(); err != nil || exists {
				t.Fatalf("recovery left materialization pending: exists=%v err=%v", exists, err)
			}
		})
	}
}

func TestInitializeShowsUntrackedFilesButNotPrivateState(t *testing.T) {
	repo, err := InitializeLocal(filepath.Join(t.TempDir(), "metadata"))
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(repo.Directory, stateDirectoryName)
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(state, "private"), filepath.Join(repo.Directory, "unexpected")} {
		if err := os.WriteFile(path, []byte("untracked\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertGitStatus(t, repo, "?? unexpected\n")
}

func assertGitStatus(t *testing.T, repo *Managed, expected string) {
	t.Helper()
	status, err := repo.RunGit(nil, 64<<10, "status", "--porcelain=v1")
	if err != nil || string(status) != expected {
		t.Fatalf("git status=%q err=%v; want %q", status, err, expected)
	}
}
