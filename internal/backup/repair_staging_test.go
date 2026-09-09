package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/repository"
)

func stageRepairFixture(t *testing.T, count int) (*integrationHarness, []format.PackEntry) {
	t.Helper()
	h := newIntegrationHarness(t)
	h.options.PackTarget, h.options.PartSize, h.options.MetadataPartSize = 1<<20, 128, 1<<20
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024)
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
	if len(parts) < count+1 {
		t.Fatal("fixture needs additional unstaged parts")
	}
	stop := errors.New("saved repair candidate")
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "forward-repair-candidate-staged" {
			return stop
		}
		return nil
	}
	for _, part := range parts[:count] {
		if _, err := RepairDataPart(ctx, interrupted, "local", part.PackHash, part.PartNumber); !errors.Is(err, stop) {
			t.Fatalf("stage repair fixture: %v", err)
		}
	}
	return h, parts
}

func TestRepairDescriptorHandoffPreservesOldOrNewCandidate(t *testing.T) {
	for _, point := range []string{"repair-descriptors-staged", "forward-repair-candidate-staged"} {
		t.Run(point, func(t *testing.T) {
			h, parts := stageRepairFixture(t, 1)
			before := loadTestTransaction(t, h.options)
			originalPath := filepath.Join(h.options.transactionFilesPath(), before.DataPartsFile.RelativePath)
			original, err := os.ReadFile(originalPath)
			if err != nil {
				t.Fatal(err)
			}
			stop := errors.New("interrupted repair descriptor handoff")
			interrupted := h.options
			interrupted.failurePoint = func(observed string) error {
				if observed == point {
					return stop
				}
				return nil
			}
			part := parts[1]
			attempt, err := RepairDataPart(context.Background(), interrupted, "local", part.PackHash, part.PartNumber)
			if !errors.Is(err, stop) {
				t.Fatalf("handoff checkpoint: %v", err)
			}
			pending := loadTestTransaction(t, h.options)
			adopted := point == "forward-repair-candidate-staged"
			if (pending.DataPartCount == 2) != adopted || (pending.DataPartsFile != before.DataPartsFile) != adopted {
				t.Fatalf("descriptor reference changed outside the control boundary: %+v", pending.DataPartsFile)
			}
			preserved, err := os.ReadFile(originalPath)
			if err != nil || !bytes.Equal(preserved, original) {
				t.Fatalf("old descriptor bytes were replaced or removed: %v", err)
			}
			resuming := h.options
			if adopted {
				resuming = withWriterTransport(h, func(base http.RoundTripper) http.RoundTripper {
					return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
						return request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/objects/")
					}}
				})
			}
			result, err := RepairDataPart(context.Background(), resuming, "local", part.PackHash, part.PartNumber)
			if err != nil || result.CommitID == "" || adopted && result.NewObjectID != attempt.NewObjectID {
				t.Fatalf("repair did not reuse/resume its durable handoff: %+v %v", result, err)
			}
			if _, err := Verify(context.Background(), h.options, 1, result.CommitID); err != nil {
				t.Fatalf("completed handoff is unverifiable: %v", err)
			}
		})
	}
}

func TestRepairDescriptorValidationCannotReplaceUsableControl(t *testing.T) {
	for _, defect := range []string{"duplicate-part", "duplicate-path", "catalog-mismatch", "oversized-record", "wrong-count", "wrong-reference", "capacity"} {
		t.Run(defect, func(t *testing.T) {
			h, _ := stageRepairFixture(t, 2)
			run, err := openRuntime(h.options, true)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = run.close() }()
			txn, err := run.loadTransaction()
			if err != nil {
				t.Fatal(err)
			}
			controlPath := filepath.Join(h.options.statePath(), transactionFilename)
			original, err := os.ReadFile(controlPath)
			if err != nil {
				t.Fatal(err)
			}
			var parts []stagedDataPart
			if err := run.walkDataParts(txn, func(_ uint64, part stagedDataPart) error {
				parts = append(parts, part)
				return nil
			}); err != nil || len(parts) != 2 {
				t.Fatalf("fixture descriptors: %d %v", len(parts), err)
			}
			replacement := parts[1]
			switch defect {
			case "duplicate-part":
				replacement.Entry = parts[0].Entry
			case "duplicate-path":
				replacement.RelativePath = parts[0].RelativePath
			case "catalog-mismatch":
				replacement.Entry.PartSize++
			case "oversized-record":
				replacement.RelativePath = strings.Repeat("x", maximumDataPartRecordBytes)
			case "wrong-count":
				txn.DataPartCount++
			case "wrong-reference":
				txn.DataPartsFile.Size++
			case "capacity":
				run.options.SpaceReserveBytes = ^uint64(0)
			}
			if defect == "wrong-count" || defect == "wrong-reference" {
				err = run.saveTransaction(txn)
			} else {
				err = run.rewriteDataParts(txn, 1, replacement)
				if defect != "oversized-record" && defect != "capacity" {
					if err != nil {
						t.Fatalf("could not construct the invalid candidate: %v", err)
					}
					err = run.saveTransaction(txn)
				}
			}
			if err == nil {
				t.Fatal("invalid repair progress was accepted")
			}
			run.options.SpaceReserveBytes = h.options.SpaceReserveBytes
			preserved, err := os.ReadFile(controlPath)
			if err != nil || !bytes.Equal(original, preserved) {
				t.Fatalf("invalid save replaced usable control: %v", err)
			}
			pending, err := run.loadTransaction()
			if err != nil || pending.DataPartCount != 2 {
				t.Fatalf("last usable candidate did not survive: %v", err)
			}
		})
	}
}
