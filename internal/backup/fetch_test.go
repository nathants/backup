package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/repository"
)

func TestFetchedFastForwardPreservesDirtyMetadata(t *testing.T) {
	for _, change := range []string{"ignore", ".publickeys", "mirrors.tsv", "index.tsv", "missing", "mode", "symlink", "untracked"} {
		t.Run(change, func(t *testing.T) {
			h := newFetchTestHarness(t)
			base, _ := advanceTestMetadataRemote(t, h)
			repoPath := h.options.repositoryPath()
			dirtyPath := change
			switch change {
			case "missing":
				dirtyPath = "ignore"
				if err := os.Remove(filepath.Join(repoPath, dirtyPath)); err != nil {
					t.Fatal(err)
				}
			case "mode":
				dirtyPath = "ignore"
				if err := os.Chmod(filepath.Join(repoPath, dirtyPath), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				dirtyPath = "ignore"
				outside := filepath.Join(t.TempDir(), "ignore")
				if err := os.WriteFile(outside, []byte("^\\./secret$\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(repoPath, dirtyPath)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(repoPath, dirtyPath)); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(repoPath, dirtyPath), []byte("^\\./secret$\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotTestMetadata(t, repoPath)
			run, err := openRuntime(h.options, true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = run.close() }()
			materializing := false
			run.repo.MaterializationFailurePoint = func(string) error {
				materializing = true
				return nil
			}
			_, history, err := run.validatedHead(true)
			if history != nil {
				_ = history.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "local changes") || !strings.Contains(err.Error(), dirtyPath) {
				t.Errorf("dirty fast-forward was not refused with its path: %v", err)
			}
			if materializing {
				t.Error("dirty fast-forward began durable materialization")
			}
			if head, err := run.repo.Head(); err != nil || head != base {
				t.Errorf("local head changed: %s %v", head, err)
			}
			after := snapshotTestMetadata(t, repoPath)
			if len(before) != len(after) {
				t.Errorf("metadata entry count changed: %d -> %d", len(before), len(after))
			}
			for name, prior := range before {
				if after[name] != prior {
					t.Errorf("local metadata entry %q changed", name)
				}
			}
		})
	}
}

func TestAddRefusesRemoteAdvanceWithoutLosingIgnoreOrPlan(t *testing.T) {
	h := newFetchTestHarness(t)
	ctx := context.Background()
	ignorePath := filepath.Join(h.options.repositoryPath(), "ignore")
	ignore := []byte("^\\./secret$\n")
	if err := os.WriteFile(ignorePath, ignore, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "secret"), []byte("not for backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	// With an unchanged remote, ordinary mutable configuration edits still work.
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatalf("add with unchanged remote rejected local ignore edit: %v", err)
	}
	var before bytes.Buffer
	_, err := DiffCandidate(h.options, func(diff Diff) error {
		if diff.New != nil && diff.New.Path == "./secret" {
			t.Error("initial plan included excluded file")
		}
		if diff.New != nil {
			before.WriteString(diff.New.Path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	txnPath := filepath.Join(h.options.statePath(), transactionFilename)
	planBefore, err := os.ReadFile(txnPath)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := advanceTestMetadataRemote(t, h)
	if _, err := Add(ctx, h.options, false); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Errorf("add did not reject dirty fast-forward: %v", err)
	}
	if after, err := os.ReadFile(ignorePath); err != nil || !bytes.Equal(after, ignore) {
		t.Errorf("local ignore was lost: %q %v", after, err)
	}
	if after, err := os.ReadFile(txnPath); err != nil || !bytes.Equal(after, planBefore) {
		t.Errorf("existing add plan control was replaced: %v", err)
	}
	var after bytes.Buffer
	_, err = DiffCandidate(h.options, func(diff Diff) error {
		if diff.New != nil && diff.New.Path == "./secret" {
			t.Error("refused add included excluded file in plan")
		}
		if diff.New != nil {
			after.WriteString(diff.New.Path)
		}
		return nil
	})
	if err != nil || after.String() != before.String() {
		t.Errorf("existing plan changed: before=%q after=%q err=%v", before.String(), after.String(), err)
	}
	if head := strings.TrimSpace(runGit(t, "-C", h.options.repositoryPath(), "rev-parse", "HEAD")); head != base {
		t.Errorf("add advanced local head to %s", head)
	}
}

func TestFindRefusesDirtyFastForwardThenAcceptsCleanRetry(t *testing.T) {
	h := newFetchTestHarness(t)
	base, remote := advanceTestMetadataRemote(t, h)
	ignorePath := filepath.Join(h.options.repositoryPath(), "ignore")
	prior, err := os.ReadFile(ignorePath)
	if err != nil {
		t.Fatal(err)
	}
	local := []byte("^\\./secret$\n")
	if err := os.WriteFile(ignorePath, local, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(h.options, ".", "HEAD", nil, nil); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Errorf("find did not reject dirty fast-forward: %v", err)
	}
	if after, err := os.ReadFile(ignorePath); err != nil || !bytes.Equal(after, local) {
		t.Errorf("find discarded local ignore: %q %v", after, err)
	}
	if head := strings.TrimSpace(runGit(t, "-C", h.options.repositoryPath(), "rev-parse", "HEAD")); head != base {
		t.Errorf("refused find advanced local head to %s", head)
	}
	// Model the operator saving their edits separately and restoring the local
	// base bytes. Comparing against the remote tree would wrongly reject this.
	if err := os.WriteFile(ignorePath, prior, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(h.options, ".", "HEAD", nil, nil); err != nil {
		t.Fatalf("clean fast-forward retry failed: %v", err)
	}
	if head := strings.TrimSpace(runGit(t, "-C", h.options.repositoryPath(), "rev-parse", "HEAD")); head != remote {
		t.Fatalf("clean retry did not fast-forward: %s != %s", head, remote)
	}
	if after, err := os.ReadFile(ignorePath); err != nil || string(after) != "^\\./remote-only$\n" {
		t.Fatalf("clean retry did not materialize remote ignore: %q %v", after, err)
	}
}

func newFetchTestHarness(t *testing.T) *integrationHarness {
	t.Helper()
	h := newIntegrationHarness(t)
	if _, err := initializePublished(context.Background(), h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	return h
}

func advanceTestMetadataRemote(t *testing.T, h *integrationHarness) (string, string) {
	t.Helper()
	repoPath := h.options.repositoryPath()
	history, err := (repository.Validator{Repo: repoPath, Limits: format.DefaultLimits()}).ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	base := testHistoryTip(t, history)
	blobs := testStateBlobs(t, base.State)
	blobs["ignore"] = []byte("^\\./remote-only$\n")
	repo := &repository.Managed{Directory: repoPath}
	remote, err := repo.CreateCommit(base.CommitID, blobs, "remote advance")
	if err != nil {
		t.Fatal(err)
	}
	runGit(t, "--git-dir", h.bare, "fetch", repoPath, remote+":refs/heads/main")
	return base.CommitID, remote
}

type testMetadataEntry struct {
	mode os.FileMode
	data string
}

func snapshotTestMetadata(t *testing.T, directory string) map[string]testMetadataEntry {
	t.Helper()
	result := make(map[string]testMetadataEntry)
	for _, name := range append(append([]string(nil), repository.RequiredBlobNames...), "untracked") {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var data string
		if info.Mode()&os.ModeSymlink != 0 {
			data, err = os.Readlink(path)
		} else {
			var raw []byte
			raw, err = os.ReadFile(path)
			data = string(raw)
		}
		if err != nil {
			t.Fatal(err)
		}
		result[name] = testMetadataEntry{mode: info.Mode(), data: data}
	}
	return result
}
