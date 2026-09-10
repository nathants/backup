package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"backup/internal/format"
	"backup/internal/repository"
)

func TestAccumulatedRepairProgressSurvivesRestart(t *testing.T) {
	for _, action := range []string{"commit", "reset"} {
		t.Run(action, func(t *testing.T) {
			h := newIntegrationHarness(t)
			h.options.PartSize = 128
			ctx := context.Background()
			if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 24<<10)
			if _, err := rand.Read(payload); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.root, "payload"), payload, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			base, err := Commit(ctx, h.options)
			if err != nil {
				t.Fatal(err)
			}
			history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(base.CommitID)
			if err != nil {
				t.Fatal(err)
			}
			parts := testPackEntries(t, testHistoryTip(t, history).State)
			if err := history.Close(); err != nil {
				t.Fatal(err)
			}
			const repairs = 128 // The former whole-descriptor ceiling failed at 114.
			if len(parts) < repairs {
				t.Fatalf("need %d ciphertext parts, got %d", repairs, len(parts))
			}
			stop := errors.New("interrupted after durable repair candidate")
			interrupted := h.options
			interrupted.failurePoint = func(point string) error {
				if point == "forward-repair-candidate-staged" {
					return stop
				}
				return nil
			}
			// Reverse catalog order so append-order acknowledgements cannot be
			// accidentally interpreted as positions in a sorted pack catalog.
			for index := repairs - 1; index >= 0; index-- {
				part := parts[index]
				if _, err := RepairDataPart(ctx, interrupted, "local", part.PackHash, part.PartNumber); !errors.Is(err, stop) {
					t.Fatalf("repair %d cannot resume the saved candidate: %v", repairs-index, err)
				}
			}
			pending := loadTestTransaction(t, h.options)
			if pending.DataPartsFile.Size <= 64<<10 {
				t.Fatalf("regression did not exceed the former descriptor ceiling: %d", pending.DataPartsFile.Size)
			}
			if action == "reset" {
				if err := Reset(h.options); err != nil {
					t.Fatalf("reset accumulated repair: %v", err)
				}
				result, err := Commit(ctx, h.options)
				if err != nil || !result.NoChanges || result.CommitID != base.CommitID {
					t.Fatalf("reset changed the published base: %+v %v", result, err)
				}
				return
			}
			result, err := Commit(ctx, h.options)
			if err != nil || result.CommitID == base.CommitID || len(result.CompleteMirrors) != 1 {
				t.Fatalf("commit accumulated repair: %+v %v", result, err)
			}
			if _, err := Verify(ctx, h.options, 1, result.CommitID); err != nil {
				t.Fatalf("verify accumulated repair: %v", err)
			}
			for _, part := range parts[:repairs] {
				if _, err := os.Stat(filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)); err != nil {
					t.Fatalf("repair removed the old immutable object: %v", err)
				}
			}
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(h.secretKey))
			target := t.TempDir()
			if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./payload$`, Revision: result.CommitID, TargetRoot: target}); err != nil {
				t.Fatalf("restore repaired catalog: %v", err)
			}
			restored, err := os.ReadFile(filepath.Join(target, "payload"))
			if err != nil || !bytes.Equal(restored, payload) {
				t.Fatalf("restored repaired bytes differ: %v", err)
			}
		})
	}
}
