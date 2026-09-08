package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func TestInitialLocalWorkflowWithoutRemotes(t *testing.T) {
	h := newIntegrationHarness(t)
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.configPath); err != nil {
		t.Fatal(err)
	}
	options := h.options
	options.ClientFactory = func(context.Context, localconfig.Mirror) (*objectstore.Client, error) {
		return nil, fmt.Errorf("unexpected network client during local preparation")
	}
	ctx := context.Background()
	result, err := initWithKeys(ctx, options, h.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if result.RepositoryUUID == "" {
		t.Fatalf("init claimed publication: %+v", result)
	}
	if err := os.WriteFile(filepath.Join(h.root, "keep"), []byte("first payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "omit"), []byte("omit"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, ".backup", "ignore"), []byte("^\\./omit$\n"), 0644); err != nil {
		t.Fatal(err)
	}
	add, err := Add(ctx, options, false)
	if err != nil || add.Entries != 1 || add.BaseCommit != "" {
		t.Fatalf("local add: %+v %v", add, err)
	}
	n, err := DiffCandidate(options, func(d Diff) error {
		if d.New == nil || d.New.Path != "./keep" {
			t.Errorf("unexpected diff: %+v", d)
		}
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("local diff: %d %v", n, err)
	}
	if err := Reset(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, options); err == nil {
		t.Fatal("commit without configuration succeeded")
	}
	if err := os.WriteFile(h.configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "later"), []byte("not planned"), 0600); err != nil {
		t.Fatal(err)
	}
	committed, err := Commit(ctx, h.options)
	if err != nil || !isCommitID(committed.CommitID) || len(committed.CompleteMirrors) != 1 {
		t.Fatalf("first commit: %+v %v", committed, err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
		t.Fatal(err)
	}
	var paths []string
	if _, err := Find(h.options, ".*", "HEAD", nil, func(e format.IndexEntry) error { paths = append(paths, e.Path); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "./keep" {
		t.Fatalf("first snapshot path set: %v", paths)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	target := t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: ".*", Revision: committed.CommitID, TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "keep")); err != nil || string(data) != "first payload" {
		t.Fatalf("first backup restore: %q %v", data, err)
	}
	if err := os.Rename(h.bare, h.bare+".offline"); err != nil {
		t.Fatal(err)
	}
	recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: committed.CommitID, Destination: filepath.Join(t.TempDir(), "recovered.git")})
	if err != nil || recovered.RecoveredTip != committed.CommitID {
		t.Fatalf("first backup recovery without Git remote: %+v %v", recovered, err)
	}
}

// Unrelated history/repair tests need a completed empty base. Exercise the real
// public lifecycle with an explicit empty plan, not the old init publication.
func initializePublished(ctx context.Context, options Options, publicKey []byte) (result SnapshotResult, returnErr error) {
	if _, err := initWithKeys(ctx, options, publicKey); err != nil {
		return SnapshotResult{}, err
	}
	// This fixture starts with only a trusted config in its source root. Keep
	// that fixture file outside the initial path set, without adding an ignore
	// rule to the genesis. Restore it for subsequent source-scanning tests.
	if filepath.Dir(options.ConfigPath) == options.Root {
		original := options.ConfigPath
		options.ConfigPath = filepath.Join(options.Root, ".backup", operationalStateDirName, "fixture-config")
		if err := os.Rename(original, options.ConfigPath); err != nil {
			return SnapshotResult{}, err
		}
		defer func() { returnErr = errors.Join(returnErr, os.Rename(options.ConfigPath, original)) }()
	}
	plan, err := Add(ctx, options, true)
	if err != nil {
		return SnapshotResult{}, err
	}
	if plan.Entries != 0 {
		return SnapshotResult{}, fmt.Errorf("published-base fixture must start empty, got %d planned paths", plan.Entries)
	}
	return Commit(ctx, options)
}

func TestInitialPublicationRestartBoundaries(t *testing.T) {
	for _, point := range []string{"initial-remote-pinned", "genesis-transaction-recorded", "local-commit-recorded", "materialization-blob-FORMAT", "local-commit-accepted", "metadata-staged", "git-push-intent-recorded", "git-push-returned", "git-push-confirmed", "metadata-part-created-before-ack", "metadata-part-acknowledged", "metadata-manifest-created-before-ack", "genesis-plan-handed-off", "commit-capture-started", "completed-pack-recorded"} {
		t.Run(point, func(t *testing.T) {
			h := newIntegrationHarness(t)
			h.options.PartSize = 1 << 20
			h.options.MetadataPartSize = 1 << 20
			ctx := context.Background()
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.root, "payload"), []byte("captured first data"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			stopped := false
			opts := h.options
			opts.failurePoint = func(p string) error {
				if p == point && !stopped {
					stopped = true
					return fmt.Errorf("interrupted %s", p)
				}
				return nil
			}
			if result, err := Commit(ctx, opts); err == nil || !stopped || result.CommitID != "" {
				t.Fatalf("did not interrupt %s: %+v %v stopped=%v", point, result, err, stopped)
			}
			if err := os.WriteFile(filepath.Join(h.root, "after-add"), []byte("excluded"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := Commit(ctx, h.options)
			if err != nil {
				t.Fatal(err)
			}
			if !isCommitID(result.CommitID) || len(result.CompleteMirrors) != 1 {
				t.Fatalf("resume result: %+v", result)
			}
			var payload bool
			if _, err := Find(h.options, ".*", "HEAD", nil, func(e format.IndexEntry) error {
				if e.Path == "./after-add" {
					t.Error("resume included post-add path")
				}
				payload = payload || e.Path == "./payload"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !payload {
				t.Fatal("resume returned genesis instead of data snapshot")
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatal(err)
			}
			history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory("HEAD")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = history.Close() }()
			if history.Len() != 2 {
				t.Fatalf("first backup must contain exactly genesis plus snapshot, got %d", history.Len())
			}
		})
	}
}

func TestInitialResetPreservesPreparation(t *testing.T) {
	for _, point := range []string{"genesis-transaction-recorded", "local-commit-recorded", "local-commit-accepted", "metadata-staged"} {
		t.Run(point, func(t *testing.T) {
			h := newIntegrationHarness(t)
			h.options.MetadataPartSize = 1 << 20
			ctx := context.Background()
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			formatPath := filepath.Join(h.root, ".backup", "FORMAT")
			identity, err := os.ReadFile(formatPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			opts := h.options
			opts.failurePoint = func(p string) error {
				if p == point {
					return fmt.Errorf("stop")
				}
				return nil
			}
			if _, err := Commit(ctx, opts); err == nil {
				t.Fatal("expected interrupted genesis")
			}
			if err := Reset(h.options); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(formatPath)
			if err != nil || !bytes.Equal(identity, after) {
				t.Fatalf("reset lost identity: %v", err)
			}
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err == nil {
				t.Fatal("reinit overwrote preparation")
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInitialPublicationNeverAdoptsExistingRemote(t *testing.T) {
	ctx := context.Background()
	owner := newIntegrationHarness(t)
	published, err := initializePublished(ctx, owner.options, owner.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	h := newIntegrationHarness(t)
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.ReplaceAll(config, []byte(h.bare), []byte(owner.bare))
	if err := os.WriteFile(h.configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("first commit adopted or replaced an existing repository")
	}
	if got := strings.TrimSpace(runGit(t, "--git-dir", owner.bare, "rev-parse", "refs/heads/main")); got != published.CommitID {
		t.Fatalf("changed existing remote: %s", got)
	}
	if err := Reset(h.options); err == nil {
		t.Fatal("reset abandoned ambiguous genesis push")
	}
	if _, err := Add(ctx, h.options, false); err == nil {
		t.Fatal("add discarded unfinished bootstrap")
	}
	var resolved string
	if _, err := Find(h.options, ".*", "HEAD", func(id string) error { resolved = id; return nil }, nil); err == nil || resolved != "" {
		t.Fatalf("read adopted another repository: %s %v", resolved, err)
	}
}

func TestInitialConfigurationAndIdentityChecks(t *testing.T) {
	for _, name := range []string{"FORMAT", "ignore", ".publickeys", "mirrors.tsv", "index.tsv", "unrelated"} {
		t.Run(name, func(t *testing.T) {
			h := newIntegrationHarness(t)
			ctx := context.Background()
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(h.root, ".backup", name)
			var data []byte
			if name == "ignore" {
				data = []byte("^\\./secret$\n")
			} else {
				data = []byte("corrupted\n")
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err == nil {
				t.Fatalf("accepted changed %s", name)
			}
			if refs := strings.TrimSpace(runGit(t, "--git-dir", h.bare, "for-each-ref", "--format=%(objectname)")); refs != "" {
				t.Fatalf("published before configuration validation: %s", refs)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, data) {
				t.Fatalf("clobbered local edits: %q %v", after, err)
			}
		})
	}
}

func TestInitialEmptyAndDisappearedPlans(t *testing.T) {
	for _, allowEmpty := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow-empty-%t", allowEmpty), func(t *testing.T) {
			h := newIntegrationHarness(t)
			ctx := context.Background()
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.root, ".backup", "ignore"), []byte("^\\./\\.backup-config$\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err == nil {
				t.Fatal("unapproved empty first add succeeded")
			}
			path := filepath.Join(h.root, "payload")
			if err := os.WriteFile(path, []byte("gone"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, allowEmpty); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			result, err := Commit(ctx, h.options)
			if allowEmpty {
				if err != nil || !isCommitID(result.CommitID) || len(result.CompleteMirrors) != 1 {
					t.Fatalf("explicit empty commit: %+v %v", result, err)
				}
			} else if err == nil || result.CommitID != "" {
				t.Fatalf("disappeared plan reported genesis as data success: %+v %v", result, err)
			}
		})
	}
}

func TestInitialRemoteBindingIsPinnedAcrossRestart(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	original, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	configured := bytes.ReplaceAll(original, []byte("branch\tmain\n"), []byte("branch\tarchive/home\n"))
	if err := os.WriteFile(h.configPath, configured, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	opts := h.options
	opts.failurePoint = func(p string) error {
		if p == "initial-remote-pinned" {
			return fmt.Errorf("stop")
		}
		return nil
	}
	if _, err := Commit(ctx, opts); err == nil {
		t.Fatal("pin checkpoint did not interrupt")
	}
	if err := os.WriteFile(h.configPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("resume changed pinned branch")
	}
	if err := os.WriteFile(h.configPath, configured, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(runGit(t, "--git-dir", h.bare, "rev-parse", "refs/heads/archive/home")); got != result.CommitID {
		t.Fatalf("configured branch tip: %s", got)
	}
}

func initWithKeys(ctx context.Context, options Options, publicKey []byte) (InitResult, error) {
	result, err := Init(ctx, options)
	if err != nil {
		return result, err
	}
	return result, os.WriteFile(filepath.Join(options.Root, ".backup", ".publickeys"), []byte(fmt.Sprintf("%x\n", publicKey)), 0644)
}
