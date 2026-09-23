package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func damageReplanObservations(t *testing.T, options Options, missing bool) {
	t.Helper()
	run, err := openRuntime(options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	if txn.Plan.ObservationsFile == nil {
		t.Fatal("fixture lacks observations")
	}
	path, err := run.stagedPath(txn.Plan.ObservationsFile.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if missing {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReplanCacheIsNotRequiredByOtherCommands(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%t", missing), func(t *testing.T) {
			ctx := context.Background()
			options, _ := newReplanPreparation(t)
			if _, err := Replan(ctx, options); err != nil {
				t.Fatal(err)
			}
			damageReplanObservations(t, options, missing)
			if _, err := Replan(ctx, options); err == nil || !strings.Contains(err.Error(), "observations") {
				t.Fatalf("damaged cache reused: %v", err)
			}
			if n, err := DiffCandidate(options, nil); err != nil || n != 2 {
				t.Fatalf("cache blocked diff: %d %v", n, err)
			}
			if _, err := Add(ctx, options, false); err != nil {
				t.Fatalf("cache blocked fresh add: %v", err)
			}
			if _, err := Replan(ctx, options); err != nil {
				t.Fatal(err)
			}
			damageReplanObservations(t, options, missing)
			if err := Reset(options); err != nil {
				t.Fatalf("cache blocked reset: %v", err)
			}
		})
	}
}

func TestCommitResumesWithoutObservationCache(t *testing.T) {
	ctx := context.Background()
	h := newIntegrationHarness(t)
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "keep"), []byte("current content"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Replan(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	damageReplanObservations(t, h.options, false)
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "commit-capture-started" {
			return fmt.Errorf("capture stop")
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); err == nil || !strings.Contains(err.Error(), "capture stop") {
		t.Fatalf("cache blocked capture: %v", err)
	}
	damageReplanObservations(t, h.options, true)
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatalf("cache blocked resume: %v", err)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	target := t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./keep$`, Revision: "HEAD", TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "keep")); err != nil || string(data) != "current content" {
		t.Fatalf("restored bytes: %q %v", data, err)
	}
}

func TestReplanRetryReclaimsUnusedGenerationsBeforeBuilding(t *testing.T) {
	ctx := context.Background()
	options, write := newReplanPreparation(t)
	path := filepath.Join(options.Root, ".backup", operationalStateDirName, "transaction-files", "plans")
	options.failurePoint = func(point string) error {
		if point == "replan-built" {
			return fmt.Errorf("stop before publish")
		}
		return nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := Replan(ctx, options); err == nil || !strings.Contains(err.Error(), "stop before publish") {
			t.Fatalf("missing failure: %v", err)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 2 {
			t.Fatalf("retry retained unused generations: count=%d err=%v", len(entries), err)
		}
		if n, err := DiffCandidate(options, nil); err != nil || n != 2 {
			t.Fatalf("cleanup lost active plan: %d %v", n, err)
		}
	}
	options.failurePoint = nil
	write(".backup/ignore", "[\n")
	if _, err := Add(ctx, options, false); err == nil {
		t.Fatal("invalid ignore accepted")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("add did not reclaim stale generations before validation/build: %d %v", len(entries), err)
	}
	write(".backup/ignore", "")
	if result, err := Replan(ctx, options); err != nil || result.Scan.ReusedFiles != 2 {
		t.Fatalf("cleanup lost the authoritative observations: %+v %v", result, err)
	}
}

func TestReplanCleanupProtectsEveryReferencedGeneration(t *testing.T) {
	options, _ := newReplanPreparation(t)
	ctx := context.Background()
	if _, err := Replan(ctx, options); err != nil {
		t.Fatal(err)
	}
	run, err := openRuntime(options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	copyRef := func(ref stagedFileRef, relative string) stagedFileRef {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(run.options.transactionFilesPath(), filepath.Dir(relative)), 0700); err != nil {
			t.Fatal(err)
		}
		data, err := run.readStagedRef(ref, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		next, err := run.ensureStagedBytes(relative, data, stagedFileRef{})
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	cache := copyRef(*txn.Plan.ObservationsFile, "plans/retained-observations/nested/rows.tsv")
	txn.Plan.ObservationsFile = &cache
	txn.Plan.ConfigFiles["ignore"] = copyRef(txn.Plan.ConfigFiles["ignore"], "plans/retained-config/ignore")
	if err := run.saveTransaction(txn); err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	options.failurePoint = func(point string) error {
		if point == "replan-built" {
			return fmt.Errorf("stop after successful build")
		}
		return nil
	}
	if _, err := Replan(ctx, options); err == nil || !strings.Contains(err.Error(), "stop after successful build") {
		t.Fatalf("cleanup deleted a referenced generation: %v", err)
	}
	if n, err := DiffCandidate(options, nil); err != nil || n != 2 {
		t.Fatalf("active plan damaged: %d %v", n, err)
	}
	options.failurePoint = nil
	result, err := Replan(ctx, options)
	if err != nil || result.Scan.ReusedFiles != 2 {
		t.Fatalf("retry lost referenced observations: %+v %v", result, err)
	}
}
