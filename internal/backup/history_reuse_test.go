package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backup/internal/repository"
)

func TestValidatedHistoryReuse(t *testing.T) {
	trace := os.Getenv("BACKUP_HISTORY_REUSE_TRACE")
	if trace == "" {
		// The hardened runner pins its executable on first use. Select an
		// instrumented real Git in a fresh process, without production hooks.
		git, err := exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
		bin := t.TempDir()
		trace = filepath.Join(bin, "trace")
		quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
		script := "#!/bin/sh\n{ printf '%s\\t' \"$@\"; printf '\\n'; } >>" + quote(trace) + "\nexec " + quote(git) + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestValidatedHistoryReuse$", "-test.v")
		command.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "BACKUP_HISTORY_REUSE_TRACE="+trace)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("history reuse subprocess: %v (context: %v)\n%s", err, ctx.Err(), output)
		}
		t.Logf("%s", output)
		return
	}

	ctx := context.Background()
	h := newIntegrationHarness(t)
	genesis, err := initializePublished(ctx, h.options, h.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{genesis.CommitID}
	for index := 1; index <= 3; index++ {
		if err := os.WriteFile(filepath.Join(h.root, ".backup", "ignore"), fmt.Appendf(nil, "^\\./excluded-%d$\n", index), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, h.options, false); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, h.options)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, result.CommitID)
	}

	t.Run("selection and mirror audits", func(t *testing.T) {
		run, err := openRuntime(h.options, true)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = run.close() }()
		_, history, err := run.validatedHead(false)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = history.Close() }()
		for _, test := range []struct {
			revision string
			index    int
		}{
			{"", 3}, {"HEAD", 3}, {ids[3], 3}, {"main", 3}, {"HEAD~1", 2}, {ids[2], 2}, {ids[0], 0},
		} {
			t.Run("resolve "+test.revision, func(t *testing.T) {
				resetGitTrace(t, trace)
				selected, err := history.ResolveRevision(test.revision)
				if err != nil || selected.CommitID != ids[test.index] {
					t.Fatalf("selected=%s err=%v", selected.CommitID, err)
				}
				if test.index > 0 && selected.Transition != repository.TransitionOrdinary {
					t.Fatalf("lost transition classification: %v", selected.Transition)
				}
				commands := readGitTrace(t, trace)
				trees := strings.Count(commands, "\tls-tree\t")
				resolutions := strings.Count(commands, "\trev-parse\t--verify\t--end-of-options\t")
				if test.revision == "" || test.revision == "HEAD" {
					if commands != "" {
						t.Fatalf("selected accepted tip with additional Git commands: %s", commands)
					}
				} else if trees < 1 || trees > 2 || resolutions != 1 || strings.Contains(commands, "\trev-list\t--reverse\t") {
					t.Errorf("selection repeated accepted history: trees=%d resolutions=%d", trees, resolutions)
				}
				t.Logf("canonical trees loaded=%d; revision resolutions=%d", trees, resolutions)
			})
		}

		t.Run("membership before state reads", func(t *testing.T) {
			tree := strings.TrimSpace(runGit(t, "-C", run.repo.Directory, "rev-parse", ids[3]+"^{tree}"))
			outside := strings.TrimSpace(runGit(t, "-C", run.repo.Directory, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit-tree", tree, "-p", ids[3], "-m", "unaccepted no-change edge"))
			resetGitTrace(t, trace)
			if _, err := history.ResolveRevision(outside); err == nil || !strings.Contains(err.Error(), "not in the validated primary history") {
				t.Fatalf("unaccepted revision: %v", err)
			}
			if commands := readGitTrace(t, trace); strings.Contains(commands, "\tls-tree\t") || strings.Contains(commands, "\tcat-file\t") || strings.Contains(commands, "\trev-list\t") {
				t.Fatal("parsed unaccepted history before checking membership")
			}
		})

		client, err := run.client(ctx, run.config.Mirrors[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []int{0, len(ids) - 1} {
			t.Run(fmt.Sprintf("audit chain %d", target), func(t *testing.T) {
				resetGitTrace(t, trace)
				if err := run.auditChain(ctx, client, "local", history, target, nil); err != nil {
					t.Fatal(err)
				}
				commands := readGitTrace(t, trace)
				if commands != "" {
					t.Errorf("mirror-chain audit reread accepted metadata: trees=%d", strings.Count(commands, "\tls-tree\t"))
				}
			})
		}
	})

	t.Run("diff reads but never publishes cache", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(h.root, "diff-only-file"), []byte("planned difference"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, h.options, false); err != nil {
			t.Fatal(err)
		}
		cachePath := filepath.Join(h.options.statePath(), validatedAncestorFile)
		validCache, err := os.ReadFile(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(cachePath, validCache, 0o600); err != nil {
				t.Error(err)
			}
		})
		for _, kind := range []string{"valid", "corrupt", "missing"} {
			t.Run(kind, func(t *testing.T) {
				var before os.FileInfo
				cacheBytes := validCache
				if kind == "missing" {
					if err := os.Remove(cachePath); err != nil {
						t.Fatal(err)
					}
				} else {
					if kind == "corrupt" {
						cacheBytes = []byte("{}\n")
					}
					if err := os.WriteFile(cachePath, cacheBytes, 0o600); err != nil {
						t.Fatal(err)
					}
					before, err = os.Stat(cachePath)
					if err != nil {
						t.Fatal(err)
					}
				}
				resetGitTrace(t, trace)
				if changes, err := DiffCandidate(h.options, nil); err != nil || changes == 0 {
					t.Fatalf("diff lost planned changes: %d %v", changes, err)
				}
				wantTrees := len(ids)
				if kind == "valid" {
					wantTrees = 1
				}
				if trees := strings.Count(readGitTrace(t, trace), "\tls-tree\t"); trees != wantTrees {
					t.Errorf("diff loaded %d canonical trees, want %d", trees, wantTrees)
				}
				after, err := os.Stat(cachePath)
				if kind == "missing" {
					if !os.IsNotExist(err) {
						t.Fatalf("diff published a missing cache: %v", err)
					}
				} else {
					if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
						t.Fatalf("diff replaced or modified its cache: %v", err)
					}
					if data, err := os.ReadFile(cachePath); err != nil || string(data) != string(cacheBytes) {
						t.Fatalf("diff changed cache bytes: %v", err)
					}
				}
			})
		}
	})

	t.Run("alternate spool cleanup reuses validated ancestor", func(t *testing.T) {
		options := h.options
		options.SpoolDirectory = t.TempDir()
		options.failurePoint = func(point string) error {
			if point == "commit-capture-started" {
				return fmt.Errorf("stop before capture")
			}
			return nil
		}
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "checkpoint commit-capture-started") {
			t.Fatalf("failed to prepare interrupted capture: %v", err)
		}
		options.failurePoint = nil
		resetGitTrace(t, trace)
		if err := Reset(options); err != nil {
			t.Fatal(err)
		}
		if trees := strings.Count(readGitTrace(t, trace), "\tls-tree\t"); trees != 1 {
			t.Errorf("spool cleanup loaded %d canonical trees, want only the validated anchor", trees)
		}
		if entries, err := os.ReadDir(options.SpoolDirectory); err != nil || len(entries) != 0 {
			t.Fatalf("reset left its alternate spool: %v %v", entries, err)
		}
	})

	t.Run("resume uses validated ancestor", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(h.root, "new-file"), []byte("pending snapshot"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, h.options, false); err != nil {
			t.Fatal(err)
		}
		interrupted := h.options
		interrupted.failurePoint = func(point string) error {
			if point == "metadata-staged" {
				return fmt.Errorf("stop before primary publication")
			}
			return nil
		}
		if _, err := Commit(ctx, interrupted); err == nil || !strings.Contains(err.Error(), "checkpoint metadata-staged") {
			t.Fatalf("failed to prepare resumable local commit: %v", err)
		}
		run, err := openRuntime(h.options, true)
		if err != nil {
			t.Fatal(err)
		}
		base, err := run.historyValidator().ValidateHistory(ids[len(ids)-1])
		if err != nil {
			_ = run.close()
			t.Fatal(err)
		}
		if err := base.Close(); err != nil {
			_ = run.close()
			t.Fatal(err)
		}
		if err := run.close(); err != nil {
			t.Fatal(err)
		}
		interrupted.failurePoint = func(point string) error {
			if point == "git-push-intent-recorded" {
				return fmt.Errorf("stop after local validation")
			}
			return nil
		}
		resetGitTrace(t, trace)
		if _, err := Commit(ctx, interrupted); err == nil || !strings.Contains(err.Error(), "checkpoint git-push-intent-recorded") {
			t.Fatalf("resume did not validate and reach publication: %v", err)
		}
		commands := readGitTrace(t, trace)
		for _, ancestor := range ids[:len(ids)-1] {
			if strings.Contains(commands, "\tls-tree\t-z\t--full-tree\t"+ancestor+"\t") {
				t.Errorf("resume revalidated commit before the accepted base: %s", ancestor)
			}
		}
		t.Logf("resume canonical trees loaded=%d", strings.Count(commands, "\tls-tree\t"))
		if result, err := Commit(ctx, h.options); err != nil || result.CommitID == ids[len(ids)-1] {
			t.Fatalf("final resume: result=%#v err=%v", result, err)
		}
	})
}

func resetGitTrace(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readGitTrace(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
