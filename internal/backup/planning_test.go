package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"

	"golang.org/x/crypto/blake2b"
)

func TestAddReplacesPlanAndCommitCapturesOnlyPlannedPathsAtCommitTime(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
		t.Fatal(err)
	}
	alpha := filepath.Join(harness.root, "alpha")
	removed := filepath.Join(harness.root, "removed")
	if err := os.WriteFile(alpha, []byte("add-time alpha"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(removed, []byte("add-time removed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}

	ignorePath := filepath.Join(harness.root, ".backup", "ignore")
	if err := os.WriteFile(ignorePath, []byte("^\\./removed$\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatalf("replace add plan after editing ignore: %v", err)
	}
	var diffs []Diff
	_, err := DiffCandidate(harness.options, func(diff Diff) error {
		diffs = append(diffs, diff)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, diff := range diffs {
		if diff.New != nil && diff.New.Path == "./removed" {
			t.Fatalf("replacement plan retained ignored path: %#v", diffs)
		}
	}

	if err := os.WriteFile(ignorePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatalf("replace add plan a second time: %v", err)
	}
	planGenerations, err := os.ReadDir(filepath.Join(harness.options.transactionFilesPath(), "plans"))
	if err != nil || len(planGenerations) != 1 {
		t.Fatalf("repeated add retained superseded plans: entries=%v err=%v", planGenerations, err)
	}
	if err := os.WriteFile(alpha, []byte("commit-time alpha"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(alpha, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "late"), []byte("not planned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warnings bytes.Buffer
	options := harness.options
	options.Stderr = &warnings
	committed, err := Commit(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings.String(), "./alpha") || !strings.Contains(warnings.String(), "./removed") {
		t.Fatalf("commit did not warn about changed and removed planned paths: %q", warnings.String())
	}

	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(committed.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	index := testIndexEntries(t, testHistoryTip(t, history).State)
	var alphaEntry *format.IndexEntry
	for position := range index {
		entry := &index[position]
		switch entry.Path {
		case "./alpha":
			alphaEntry = entry
		case "./removed", "./late":
			t.Fatalf("commit included removed or post-add path: %#v", index)
		}
	}
	if alphaEntry == nil || alphaEntry.Mode != 0o640 {
		t.Fatalf("commit did not use the final planned-path state: %#v", index)
	}
	digest := blake2b.Sum512([]byte("commit-time alpha"))
	if alphaEntry.Ref != fmt.Sprintf("blake2b:%x", digest[:]) || alphaEntry.Size != uint64(len("commit-time alpha")) {
		t.Fatalf("commit index does not describe bytes captured at commit time: %#v", alphaEntry)
	}
}

func TestCommitHandlesAllPlannedPathsDisappearingAndRejectsConfigDrift(t *testing.T) {
	t.Run("all paths disappearing requires add allow-empty", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		genesis, err := initializePublished(ctx, harness.options, harness.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, ".backup", "ignore"), []byte("^\\./\\.backup-config$\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(harness.root, "ephemeral")
		if err := os.WriteFile(path, []byte("planned"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "every path selected by add disappeared") {
			t.Fatalf("unexpected non-allow-empty result: %v", err)
		}
		if head, err := (&repository.Managed{Directory: filepath.Join(harness.root, ".backup"), Branch: "main"}).Head(); err != nil || head != genesis.CommitID {
			t.Fatalf("failed empty capture changed head: %s %v", head, err)
		}
		if err := Reset(harness.options); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, ".backup", "ignore"), []byte("^\\./\\.backup-config$\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte("planned again"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, true); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, harness.options)
		if err != nil {
			t.Fatal(err)
		}
		history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(result.CommitID)
		if err != nil {
			t.Fatal(err)
		}
		if testHistoryTip(t, history).State.IndexCount != 0 {
			t.Fatalf("allow-empty disappearance committed nonempty index: %#v", testIndexEntries(t, testHistoryTip(t, history).State))
		}
	})

	t.Run("tracked configuration changed after add is refused", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, ".backup", "ignore"), []byte("^\\./other$\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "changed after add") {
			t.Fatalf("configuration drift was accepted: %v", err)
		}
	})
}

func TestCaptureWorkspaceCapacityAndExternalSpool(t *testing.T) {
	t.Run("insufficient capacity fails before capture and is resumable", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		constrained := harness.options
		constrained.SpaceReserveBytes = ^uint64(0)
		if _, err := Commit(ctx, constrained); err == nil || !strings.Contains(err.Error(), "plaintext spool capacity") {
			t.Fatalf("oversized capture was not rejected before filling staging: %v", err)
		}
		retry := harness.options
		retry.SpaceReserveBytes = 1
		if result, err := Commit(ctx, retry); err != nil || !isCommitID(result.CommitID) {
			t.Fatalf("capacity failure was not resumable: %#v %v", result, err)
		}
	})

	t.Run("external spool uses and removes repository child", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("external spool payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		options := harness.options
		options.SpoolDirectory = t.TempDir()
		options.SpaceReserveBytes = 1
		if _, err := Add(ctx, options, false); err != nil {
			t.Fatal(err)
		}
		if result, err := Commit(ctx, options); err != nil || !isCommitID(result.CommitID) {
			t.Fatalf("external-spool commit=%#v err=%v", result, err)
		}
		entries, err := os.ReadDir(options.SpoolDirectory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("external spool left plaintext state: %v %v", entries, err)
		}
	})

	t.Run("external spool inside included source is rejected", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		options := harness.options
		options.SpoolDirectory = filepath.Join(harness.root, "unsafe-spool")
		if err := os.Mkdir(options.SpoolDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, options, false); err != nil {
			t.Fatal(err)
		}
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "inside the backup root") {
			t.Fatalf("included external spool was accepted: %v", err)
		}
	})
}

func TestCompletedPackResumeSkipsCapturedPathsAndIncompletePackRestarts(t *testing.T) {
	t.Run("completed pack skips source reread", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		harness.options.PackTarget = 1
		harness.options.PartSize = 1 << 20
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct{ name, data string }{{"alpha", "alpha-original"}, {"beta", "beta-original"}} {
			if err := os.WriteFile(filepath.Join(harness.root, item.name), []byte(item.data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		completedPacks := 0
		options := harness.options
		options.failurePoint = func(point string) error {
			if point == "completed-pack-recorded" {
				completedPacks++
				if completedPacks == 2 {
					return fmt.Errorf("stop after alpha pack")
				}
			}
			return nil
		}
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "completed-pack-recorded") {
			t.Fatalf("first pack was not durably stopped: %v", err)
		}
		if err := os.Remove(filepath.Join(harness.root, "alpha")); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, harness.options)
		if err != nil {
			t.Fatalf("resume reread an already completed pack: %v", err)
		}
		t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", harness.secretKey))
		target := t.TempDir()
		if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./alpha$`, Revision: result.CommitID, TargetRoot: target}); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(filepath.Join(target, "alpha")); err != nil || string(data) != "alpha-original" {
			t.Fatalf("resumed pack bytes=%q err=%v", data, err)
		}
	})

	t.Run("incomplete pack restarts from current source", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(harness.root, "file")
		if err := os.WriteFile(path, []byte("first attempt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		unavailable := harness.options
		unavailable.ClientFactory = func(context.Context, localconfig.Mirror) (*objectstore.Client, error) {
			return nil, fmt.Errorf("offline")
		}
		if _, err := Commit(ctx, unavailable); err == nil || !strings.Contains(err.Error(), "no individual mirror acknowledged") {
			t.Fatalf("incomplete pack unexpectedly became progress: %v", err)
		}
		if err := os.WriteFile(path, []byte("second attempt"), 0o600); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, harness.options)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", harness.secretKey))
		target := t.TempDir()
		if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: result.CommitID, TargetRoot: target}); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(filepath.Join(target, "file")); err != nil || string(data) != "second attempt" {
			t.Fatalf("restarted pack bytes=%q err=%v", data, err)
		}
	})
}

func TestTransactionControlDoesNotEmbedPlanOrCatalogRows(t *testing.T) {
	harness := newIntegrationHarness(t)
	harness.options.PackTarget = 1 << 20
	harness.options.PartSize = 1 << 20
	ctx := context.Background()
	if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		name := fmt.Sprintf("distinct-plan-path-%03d", index)
		if err := os.WriteFile(filepath.Join(harness.root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(harness.options.statePath(), transactionFilename)
	control, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(control, []byte("distinct-plan-path")) || len(control) > 32<<10 {
		t.Fatalf("transaction control embedded the add plan (%d bytes)", len(control))
	}
	captureTestTransaction(t, harness)
	control, err = os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(control, []byte("distinct-plan-path")) || bytes.Contains(control, []byte("candidate_blobs")) || len(control) > 32<<10 {
		t.Fatalf("transaction control embedded cumulative candidate/catalog state (%d bytes)", len(control))
	}
}

func TestCaptureWarningsRemainBoundedAndSummarizedAcrossResume(t *testing.T) {
	harness := newIntegrationHarness(t)
	harness.options.PackTarget = 1 << 20
	harness.options.PartSize = 1 << 20
	ctx := context.Background()
	if _, err := initializePublished(ctx, harness.options, harness.publicKey); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 105; index++ {
		path := filepath.Join(harness.root, fmt.Sprintf("warning-%03d", index))
		if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 105; index++ {
		path := filepath.Join(harness.root, fmt.Sprintf("warning-%03d", index))
		if err := os.WriteFile(path, []byte("after"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var firstWarnings bytes.Buffer
	first := harness.options
	first.Stderr = &firstWarnings
	stopped := false
	first.failurePoint = func(point string) error {
		if point == "completed-pack-recorded" && !stopped {
			stopped = true
			return fmt.Errorf("stop before warning summary")
		}
		return nil
	}
	if _, err := Commit(ctx, first); err == nil || !strings.Contains(err.Error(), "completed-pack-recorded") {
		t.Fatalf("capture did not stop at completed pack: %v", err)
	}
	var resumedWarnings bytes.Buffer
	resumed := harness.options
	resumed.Stderr = &resumedWarnings
	if _, err := Commit(ctx, resumed); err != nil {
		t.Fatal(err)
	}
	combined := firstWarnings.String() + resumedWarnings.String()
	if details := strings.Count(combined, "warning: ./warning-"); details != maximumDisplayedCaptureWarnings {
		t.Fatalf("warning details=%d, want %d", details, maximumDisplayedCaptureWarnings)
	}
	if strings.Count(combined, "additional planned paths changed") != 1 || !strings.Contains(combined, "warning: 5 additional planned paths changed") {
		t.Fatalf("warning summary was missing or repeated: %q", combined)
	}
}

func TestChooseCiphertextPartSizeRetainsReserve(t *testing.T) {
	if size, err := chooseCiphertextPartSize(1_000, 900, 1_500, 100); err != nil || size != 600 {
		t.Fatalf("dynamic part size=%d err=%v", size, err)
	}
	if size, err := chooseCiphertextPartSize(100, 900, 1_500, 100); err != nil || size != 100 {
		t.Fatalf("configured part size=%d err=%v", size, err)
	}
	if _, err := chooseCiphertextPartSize(100, 1_500, 1_500, 100); err == nil {
		t.Fatal("capacity with no retained reserve was accepted")
	}
	if _, err := chooseCiphertextPartSize(100, 1, 1_500, 16); err == nil {
		t.Fatal("capacity without inode headroom was accepted")
	}
}
