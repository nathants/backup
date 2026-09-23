package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

// The added manifest has valid checksums but describes the genesis ciphertext
// as a different Git edge. Creating it needs no recipient secret or overwrite.
func pendingMetadataFixture(t *testing.T, checkpoint string) (*integrationHarness, *transaction, manifestRepresentation) {
	t.Helper()
	return stagePendingMetadataFixture(t, newIntegrationHarness(t), checkpoint)
}

func stagePendingMetadataFixture(t *testing.T, h *integrationHarness, checkpoint string) (*integrationHarness, *transaction, manifestRepresentation) {
	t.Helper()
	ctx := context.Background()
	genesis, err := initializePublished(ctx, h.options, h.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	uuid := testHistoryGenesisFormat(t, history).RepositoryUUID
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	client := testMirrorClient(t, ctx, h)
	representations, err := listManifestRepresentations(ctx, client, genesis.CommitID, uuid)
	if err != nil || len(representations) != 1 {
		t.Fatalf("genesis representations: %d %v", len(representations), err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
		t.Fatalf("healthy genesis verification: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "payload"), []byte("selected data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	interrupted := h.options
	stop := errors.New("interrupted publication")
	interrupted.failurePoint = func(point string) error {
		if point == checkpoint {
			return stop
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); !errors.Is(err, stop) {
		t.Fatalf("checkpoint %s: %v", checkpoint, err)
	}
	txn := loadTestTransaction(t, h.options)
	if txn.LocalCommit == "" || txn.LocalCommit == genesis.CommitID {
		t.Fatal("fixture did not stage a new Git revision")
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("missing metadata edge passed verification")
	}
	manifest := cloneTestManifest(representations[0].Manifest)
	manifest.TipCommit, manifest.BaseCommit = txn.LocalCommit, genesis.CommitID
	manifest.Kind, manifest.Sequence = format.BundleIncremental, 1
	falseEdge := uploadTestManifest(t, ctx, client, manifest, strings.Repeat("a", 32))
	return h, txn, falseEdge
}

func TestPendingMetadataVerificationRequiresStagedRepresentation(t *testing.T) {
	for _, checkpoint := range []string{"local-commit-accepted", "git-push-confirmed"} {
		t.Run(checkpoint, func(t *testing.T) {
			h, pending, falseEdge := pendingMetadataFixture(t, checkpoint)
			ctx := context.Background()
			pendingOptions := withWriterTransport(h, func(base http.RoundTripper) http.RoundTripper {
				return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
					body := request.Method == http.MethodGet && (strings.Contains(request.URL.Path, "/objects/") || strings.Contains(request.URL.Path, "/metadata/parts/"))
					if body {
						t.Errorf("pending verification downloaded an encrypted body: %s", request.URL.Path)
					}
					return body
				}}
			})
			verified, err := Verify(ctx, pendingOptions, 1, "HEAD")
			if err == nil || verified.Passed != 0 {
				t.Errorf("unrelated ciphertext completed the pending revision: %+v %v", verified, err)
			}
			stillPending := loadTestTransaction(t, h.options)
			if stillPending.LocalCommit != pending.LocalCommit {
				t.Fatal("verification changed the pending revision")
			}
			completed, err := Commit(ctx, h.options)
			if err != nil || completed.CommitID != pending.LocalCommit || len(completed.CompleteMirrors) != 1 {
				t.Fatalf("resume real publication: %+v %v", completed, err)
			}
			if _, err := os.Stat(filepath.Join(h.root, ".backup", operationalStateDirName, transactionFilename)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed transaction not retired: %v", err)
			}
			client := testMirrorClient(t, ctx, h)
			data, err := client.GetManifest(ctx, falseEdge.Key, falseEdge.Hash)
			if err != nil || !bytes.Equal(data, falseEdge.Data) {
				t.Fatalf("unrelated immutable manifest changed: %v", err)
			}
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
			if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
				t.Fatal(err)
			}
			recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: completed.CommitID, Destination: filepath.Join(t.TempDir(), "recovered.git")})
			if err != nil || recovered.RecoveredTip != completed.CommitID {
				t.Fatalf("completed mirror is not independently recoverable: %+v %v", recovered, err)
			}
		})
	}
}

func TestPendingCompletionLedgerCannotRetireWrongMetadata(t *testing.T) {
	h, pending, falseEdge := pendingMetadataFixture(t, "git-push-confirmed")
	// Simulate an earlier checksum-only audit recording this commit. A ledger
	// row alone must not authorize cleanup of a different staged representation.
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.recordVerified(falseEdge.Manifest.RepositoryUUID, "local", pending.LocalCommit); err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if result, err := Commit(context.Background(), blockMetadataUploads(h)); err == nil {
		t.Fatalf("bare completion ledger retired unpublished metadata: %+v", result)
	}
	preserved := loadTestTransaction(t, h.options)
	if preserved.LocalCommit != pending.LocalCommit || preserved.Metadata.ManifestHash != pending.Metadata.ManifestHash {
		t.Fatal("failed finalization discarded or substituted pending metadata")
	}
}

func blockMetadataUploads(h *integrationHarness) Options {
	return withWriterTransport(h, func(base http.RoundTripper) http.RoundTripper {
		return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
			return request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/metadata/")
		}}
	})
}

func TestForwardRepairRequiresPendingMetadataRepresentation(t *testing.T) {
	h, pending, _ := pendingMetadataFixture(t, "git-push-confirmed")
	ctx := context.Background()
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	state, err := run.loadCandidateState(pending)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	part := testPackEntries(t, state)[0]
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
	healthy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("pending data corruption was not observed")
	}
	// Lower-layer repair supplies healthy bytes without clearing quarantine.
	if err := os.WriteFile(path, healthy, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairDataPart(ctx, blockMetadataUploads(h), "local", part.PackHash, part.PartNumber); err == nil {
		t.Fatal("forward repair completed without the pinned metadata edge")
	}
	preserved := loadTestTransaction(t, h.options)
	if preserved.Kind != pending.Kind || preserved.LocalCommit != pending.LocalCommit {
		t.Fatalf("forward repair retired the pending transaction through unrelated ciphertext: kind=%s commit=%s", preserved.Kind, preserved.LocalCommit)
	}
	if _, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber); err != nil {
		t.Fatalf("forward repair did not resume after uploads recovered: %v", err)
	}
}

func TestPendingMetadataRepairAdoptsValidatedRepresentation(t *testing.T) {
	h, pending, _ := pendingMetadataFixture(t, "git-push-confirmed")
	ctx := context.Background()
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	repaired, err := RepairMetadataEdge(ctx, h.options, "local", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	adopted := loadTestTransaction(t, h.options)
	if adopted.Metadata.ManifestHash != repaired.ManifestHash || adopted.Metadata.ManifestObjectID != repaired.ManifestObjectID || adopted.Metadata.ManifestHash == pending.Metadata.ManifestHash {
		t.Fatal("validated repair was not adopted into the pending transaction")
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
		t.Fatalf("adopted repair not verifiable: %v", err)
	}
	if result, err := Commit(ctx, blockMetadataUploads(h)); err != nil || result.CommitID != pending.LocalCommit {
		t.Fatalf("adopted published representation needed another upload: %+v %v", result, err)
	}
}

func TestPendingMetadataRepairHandoffRestarts(t *testing.T) {
	for _, point := range []string{"metadata-repair-validated", "metadata-repair-published", "metadata-repair-adopted"} {
		t.Run(point, func(t *testing.T) {
			h, pending, _ := pendingMetadataFixture(t, "git-push-confirmed")
			ctx := context.Background()
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
			interrupted := h.options
			stop := errors.New("interrupted metadata repair")
			interrupted.failurePoint = func(observed string) error {
				if observed == point {
					return stop
				}
				return nil
			}
			if _, err := RepairMetadataEdge(ctx, interrupted, "local", "HEAD"); !errors.Is(err, stop) {
				t.Fatalf("repair checkpoint %s: %v", point, err)
			}
			resumed := loadTestTransaction(t, h.options)
			if resumed.LocalCommit != pending.LocalCommit {
				t.Fatal("metadata repair changed the pending Git revision")
			}
			adopted := point == "metadata-repair-adopted"
			if (resumed.Metadata.ManifestHash != pending.Metadata.ManifestHash) != adopted {
				t.Fatal("repair pin changed outside the atomic adoption boundary")
			}
			if !adopted {
				if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
					t.Fatal("unadopted representation completed the pending revision")
				}
				if _, err := RepairMetadataEdge(ctx, h.options, "local", "HEAD"); err != nil {
					t.Fatalf("retry metadata repair: %v", err)
				}
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatalf("verify adopted metadata after restart: %v", err)
			}
			if result, err := Commit(ctx, blockMetadataUploads(h)); err != nil || result.CommitID != pending.LocalCommit {
				t.Fatalf("complete after repair restart: %+v %v", result, err)
			}
			if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
				t.Fatal(err)
			}
			recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: pending.LocalCommit, Destination: filepath.Join(t.TempDir(), "recovered.git")})
			if err != nil || recovered.RecoveredTip != pending.LocalCommit {
				t.Fatalf("adopted metadata cannot recover without primary: %+v %v", recovered, err)
			}
		})
	}
}

func TestPendingMetadataSyncAndCompletionRequireOnePinnedMirror(t *testing.T) {
	h, remote := newIntegrationHarness(t), newIntegrationHarness(t)
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, []byte(fmt.Sprintf("mirror\tremote\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\n", remote.http.URL))...)
	if err := os.WriteFile(h.configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	localFactory := h.options.ClientFactory
	h.options.ClientFactory = func(ctx context.Context, pin localconfig.Mirror) (objectstore.Store, error) {
		if pin.Canonical.Name == "remote" {
			return remote.options.ClientFactory(ctx, pin)
		}
		return localFactory(ctx, pin)
	}
	h, pending, _ := stagePendingMetadataFixture(t, h, "git-push-confirmed")
	ctx := context.Background()
	if _, err := Sync(ctx, h.options, "local", "remote", "HEAD"); err == nil {
		t.Fatal("sync accepted the unrelated pending representation")
	}
	// Publish the exact local representation but retain its transaction. The
	// bogus alternative still exists and must not be the representation copied.
	interrupted := h.options
	stop := errors.New("lost manifest acknowledgement")
	interrupted.failurePoint = func(point string) error {
		if point == "metadata-manifest-created-before-ack" {
			return stop
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); !errors.Is(err, stop) {
		t.Fatalf("publish exact pending metadata: %v", err)
	}
	if _, err := Sync(ctx, h.options, "local", "remote", "HEAD"); err != nil {
		t.Fatalf("sync did not choose the transaction's representation: %v", err)
	}
	// Lose one acknowledged part only on the first mirror after both ledger
	// rows were recorded. Finalization must audit and quarantine it, then use
	// fresh complete evidence for the other individual mirror.
	partKey, err := format.MetadataPartKey(pending.Metadata.Manifest.Parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.serverRoot, filepath.FromSlash(partKey)), []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Commit(ctx, h.options)
	if err != nil || strings.Join(result.CompleteMirrors, ",") != "remote" || strings.Join(result.LaggingMirrors, ",") != "local" {
		t.Fatalf("pending completion used a bad mirror or a union: %+v %v", result, err)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
		t.Fatal(err)
	}
	recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "remote", Tip: pending.LocalCommit, Destination: filepath.Join(t.TempDir(), "recovered.git")})
	if err != nil || recovered.RecoveredTip != pending.LocalCommit {
		t.Fatalf("sole complete mirror cannot recover the pending revision: %+v %v", recovered, err)
	}
}
