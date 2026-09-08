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

func incidentHarness(t *testing.T) (*integrationHarness, format.PackEntry, string) {
	t.Helper()
	h := newIntegrationHarness(t)
	h.options.PartSize, h.options.MetadataPartSize = 1<<20, 1<<20
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "old"), []byte("old data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(snapshot.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	return h, packPartForIndexPath(t, testHistoryTip(t, history).State, "old"), snapshot.CommitID
}

func TestIntegrityIncidentPausesAndFreshVerificationRestoresEligibility(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "corrupt", true: "missing"}[missing], func(t *testing.T) {
			h, part, _ := incidentHarness(t)
			ctx := context.Background()
			path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
			healthy, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if missing {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("corrupt"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
				t.Fatal("corruption not detected")
			}
			if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			if result, err := Commit(ctx, h.options); err == nil {
				t.Fatalf("known damaged mirror accepted: %+v", result)
			}
			// Lower-layer repair alone must not restore the revoked operational claim.
			if err := os.WriteFile(path, healthy, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err == nil {
				t.Fatal("resumed without a fresh full audit")
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrityIncidentAllowsForwardRepairAfterPublication(t *testing.T) {
	h, part, _ := incidentHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "git-push-confirmed" {
			return errors.New("power interruption")
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); err == nil {
		t.Fatal("checkpoint did not interrupt")
	}
	path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
	healthy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("pending damaged revision passed")
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("pending transaction ignored corruption")
	}
	if err := Reset(h.options); err == nil {
		t.Fatal("published revision reset")
	}
	// Supply verified repair bytes from the repaired lower layer. This is not a
	// full-mirror audit and must not make the damaged pending revision successful.
	if err := os.WriteFile(path, healthy, 0600); err != nil {
		t.Fatal(err)
	}
	repaired, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.NewObjectID == part.ObjectID || repaired.CommitID == "" {
		t.Fatalf("not a forward relocation: %+v", repaired)
	}
	if _, err := Verify(ctx, h.options, 1, repaired.CommitID); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityIncidentDoesNotReuseCandidateAcknowledgements(t *testing.T) {
	h, oldPart, _ := incidentHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("different bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	captureTestTransaction(t, h)
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		t.Fatal(err)
	}
	newPart := packPartForIndexPath(t, candidate, "new")
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(h.serverRoot, "objects", oldPart.PartHash, oldPart.ObjectID)
	newPath := filepath.Join(h.serverRoot, "objects", newPart.PartHash, newPart.ObjectID)
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{oldPath, newPath} {
		if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("bad base passed")
	}
	if err := os.WriteFile(oldPath, oldBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("stale captured acknowledgement bypassed fresh candidate audit")
	}
	if err := os.WriteFile(newPath, newBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedPendingRevisionFinalizesWithoutForgingStagedAcknowledgements(t *testing.T) {
	for _, alternative := range []bool{false, true} {
		t.Run(fmt.Sprint(alternative), func(t *testing.T) {
			h, _, _ := incidentHarness(t)
			ctx := context.Background()
			if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("more data"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			interrupted := h.options
			checkpoint := "metadata-manifest-created-before-ack"
			if alternative {
				checkpoint = "git-push-returned"
			}
			interrupted.failurePoint = func(point string) error {
				if point == checkpoint {
					return errors.New("lost local acknowledgement")
				}
				return nil
			}
			if _, err := Commit(ctx, interrupted); err == nil {
				t.Fatal("not interrupted")
			}
			if alternative {
				t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
				if _, err := RepairMetadataEdge(ctx, h.options, "local", "HEAD"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatal(err)
			}
			result, err := Commit(ctx, h.options)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.CompleteMirrors) != 1 {
				t.Fatalf("not finalized: %+v", result)
			}
		})
	}
}

func TestIntegrityIncidentHealthyMirrorCanResumeWhileDamagedMirrorStaysExcluded(t *testing.T) {
	h := newIntegrationHarness(t)
	remote := newIntegrationHarness(t)
	h.options.PartSize, h.options.MetadataPartSize = 1<<20, 1<<20
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, []byte(fmt.Sprintf("mirror\tremote\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\n", remote.http.URL))...)
	if err := os.WriteFile(h.configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	localFactory := h.options.ClientFactory
	h.options.ClientFactory = func(ctx context.Context, pin localconfig.Mirror) (*objectstore.Client, error) {
		if pin.Canonical.Name == "remote" {
			return remote.options.ClientFactory(ctx, pin)
		}
		return localFactory(ctx, pin)
	}
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "old"), []byte("old data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	first, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(first.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	part := packPartForIndexPath(t, testHistoryTip(t, history).State, "old")
	_ = history.Close()
	if err := os.WriteFile(filepath.Join(remote.serverRoot, "objects", part.PartHash, part.ObjectID), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	// The healthy mirror is visited FIRST, before the newly discovered incident.
	if result, err := Verify(ctx, h.options, 1, "HEAD"); err != nil || result.Passed != 1 {
		t.Fatalf("degraded verify: %+v %v", result, err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	var reports bytes.Buffer
	ordinary := h.options
	ordinary.Stderr = &reports
	factory := h.options.ClientFactory
	ordinary.ClientFactory = func(ctx context.Context, pin localconfig.Mirror) (*objectstore.Client, error) {
		if pin.Canonical.Name == "remote" {
			t.Error("ordinary commit attempted a quarantined mirror")
		}
		return factory(ctx, pin)
	}
	result, err := Commit(ctx, ordinary)
	if err != nil || strings.Join(result.CompleteMirrors, ",") != "local" {
		t.Fatalf("healthy ordinary resume: %+v %v", result, err)
	}
	if !strings.Contains(reports.String(), "DEGRADED REDUNDANCY") {
		t.Fatalf("missing visible degradation: %s", reports.String())
	}
	// Catch up the missing new objects before immutable relocation of the old
	// corrupt key. Sync must not falsely mark this destination complete.
	if _, err := Sync(ctx, h.options, "local", "remote", "HEAD"); err == nil {
		t.Fatal("sync overwrote corrupt immutable object")
	}
	if _, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber); err != nil {
		t.Fatal(err)
	}
	// The remote still lacks the intervening new data/metadata and remains
	// excluded until full checksum-audited sync completes it.
	if _, err := Sync(ctx, h.options, "local", "remote", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if result, err := Verify(ctx, h.options, 2, "HEAD"); err != nil || result.Passed != 2 {
		t.Fatalf("repaired mirrors: %+v %v", result, err)
	}
}

func TestIntegrityIncidentAccumulatesRepairsUntilOneCandidateIsComplete(t *testing.T) {
	h, firstPart, _ := incidentHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.root, "second"), []byte("second file payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	second, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(second.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	secondPart := packPartForIndexPath(t, testHistoryTip(t, history).State, "second")
	_ = history.Close()
	paths := []string{filepath.Join(h.serverRoot, "objects", firstPart.PartHash, firstPart.ObjectID), filepath.Join(h.serverRoot, "objects", secondPart.PartHash, secondPart.ObjectID)}
	healthy := make([][]byte, 2)
	for i, path := range paths {
		healthy[i], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("corruption missed")
	}
	if err := os.WriteFile(paths[0], healthy[0], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairDataPart(ctx, h.options, "local", firstPart.PackHash, firstPart.PartNumber); err == nil {
		t.Fatal("partial repair claimed a complete revision")
	}
	if err := os.WriteFile(paths[0], []byte("bad again"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], healthy[1], 0600); err != nil {
		t.Fatal(err)
	}
	repaired, err := RepairDataPart(ctx, h.options, "local", secondPart.PackHash, secondPart.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[1], []byte("bad again"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, repaired.CommitID); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrityIncidentLedgerRebuildAndTransientFailures(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable is not corrupt", true: "single mirror rebuild"}[lost], func(t *testing.T) {
			h, _, _ := incidentHarness(t)
			ctx := context.Background()
			if lost {
				if err := os.Remove(filepath.Join(h.root, ".backup", operationalStateDirName, ledgerFilename)); err != nil {
					t.Fatal(err)
				}
				if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
					t.Fatal(err)
				}
			} else {
				unavailable := h.options
				unavailable.ClientFactory = func(context.Context, localconfig.Mirror) (*objectstore.Client, error) {
					return nil, errors.New("temporary unavailable reader")
				}
				if _, err := Verify(ctx, unavailable, 1, "HEAD"); err == nil {
					t.Fatal("unavailable mirror passed")
				}
			}
			if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
				t.Fatal(err)
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

func TestIntegrityIncidentRestoreObservationsIgnoreSupersededHistoricalMappings(t *testing.T) {
	h, part, snapshot := incidentHarness(t)
	ctx := context.Background()
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
	healthy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./old$`, Revision: snapshot, TargetRoot: target}); err == nil {
		t.Fatal("corrupt restore passed")
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("published unverified content: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("restore observation did not pause writer")
	}
	if err := Reset(h.options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, healthy, 0600); err != nil {
		t.Fatal(err)
	}
	repaired, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("superseded corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./old$`, Revision: snapshot, TargetRoot: t.TempDir()}); err == nil {
		t.Fatal("historical restore silently switched mappings")
	}
	target = t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./old$`, Revision: snapshot, CatalogRevision: repaired.CommitID, TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "old")); err != nil || string(data) != "old data" {
		t.Fatalf("restored data: %q %v", data, err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatalf("superseded damage paused healthy current revision: %v", err)
	}
}

func TestIntegrityIncidentMetadataRepairRestoresEligibilityWithoutRemovingBadAlternatives(t *testing.T) {
	for _, manifest := range []bool{false, true} {
		t.Run(map[bool]string{false: "bundle part", true: "manifest"}[manifest], func(t *testing.T) {
			h, _, snapshot := incidentHarness(t)
			ctx := context.Background()
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
			history, err := (repository.Validator{Repo: filepath.Join(h.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			reader := testMirrorClient(t, ctx, h)
			representations, err := listManifestRepresentations(ctx, reader, snapshot, testHistoryGenesisFormat(t, history).RepositoryUUID)
			_ = history.Close()
			if err != nil || len(representations) != 1 {
				t.Fatalf("manifest setup: %v %v", representations, err)
			}
			key := representations[0].Key
			if !manifest {
				key, err = format.MetadataPartKey(representations[0].Manifest.Parts[0])
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(h.serverRoot, filepath.FromSlash(key))
			if err := os.WriteFile(path, []byte("bad metadata"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
				t.Fatal("damaged chain passed")
			}
			if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err == nil {
				t.Fatal("damaged metadata chain remained eligible")
			}
			if _, err := RepairMetadataEdge(ctx, h.options, "local", snapshot); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "bad metadata" {
				t.Fatalf("old immutable representation changed: %q %v", data, err)
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
				t.Fatal(err)
			}
			if _, err := Commit(ctx, h.options); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrityIncidentForwardRepairRestartsAtDurableBoundaries(t *testing.T) {
	for _, point := range []string{"forward-repair-intent-recorded", "forward-repair-metadata-durable", "transaction-control-cleared", "forward-repair-candidate-staged", "forward-repair-completed"} {
		t.Run(point, func(t *testing.T) {
			h, part, _ := incidentHarness(t)
			ctx := context.Background()
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
			if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			interrupted := h.options
			interrupted.failurePoint = func(p string) error {
				if p == "git-push-confirmed" {
					return errors.New("interruption")
				}
				return nil
			}
			if _, err := Commit(ctx, interrupted); err == nil {
				t.Fatal("not interrupted")
			}
			path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
			healthy, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
				t.Fatal("pending corruption missed")
			}
			if err := os.WriteFile(path, healthy, 0600); err != nil {
				t.Fatal(err)
			}
			interrupted.failurePoint = func(p string) error {
				if p == point {
					return errors.New("interruption")
				}
				return nil
			}
			if _, err := RepairDataPart(ctx, interrupted, "local", part.PackHash, part.PartNumber); err == nil {
				t.Fatal("repair was not interrupted")
			}
			run, err := openRuntime(h.options, true)
			if err != nil {
				t.Fatal(err)
			}
			txn, err := run.loadTransaction()
			if err != nil {
				t.Fatal(err)
			}
			head, history, err := run.validatedHead(false)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := run.loadLedger(head.State.Format.RepositoryUUID)
			if err != nil {
				t.Fatal(err)
			}
			_ = history.Close()
			_ = run.close()
			if point != "forward-repair-completed" && ledger.ForwardRepair == "" {
				t.Fatal("forward intent disappeared before complete descendant")
			}
			if txn != nil && txn.Kind == "repair" {
				if _, err := Commit(ctx, h.options); err != nil {
					t.Fatal(err)
				}
			} else {
				if txn == nil {
					if _, err := Commit(ctx, h.options); err == nil {
						t.Fatal("ordinary no-op hid incomplete forward repair")
					}
				}
				if _, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber); err != nil {
					t.Fatal(err)
				}
			}
			verified, err := Verify(ctx, h.options, 1, "HEAD")
			if err != nil {
				t.Fatal(err)
			}
			// Prove the retired transaction's edge was preserved, not merely forgotten:
			// decrypt the complete chain with the primary metadata service unavailable.
			if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
				t.Fatal(err)
			}
			recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: verified.CommitID, Destination: filepath.Join(t.TempDir(), "recovered.git")})
			if err != nil {
				t.Fatal(err)
			}
			if recovered.RecoveredTip != verified.CommitID {
				t.Fatalf("wrong recovered descendant: %+v", recovered)
			}
		})
	}
}

func TestIntegrityIncidentPendingGenesisCannotReuseDamagedMetadata(t *testing.T) {
	h := newIntegrationHarness(t)
	h.options.MetadataPartSize = 1 << 20
	ctx := context.Background()
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "metadata-manifest-created-before-ack" {
			return errors.New("interruption")
		}
		return nil
	}
	if _, err := initializePublished(ctx, interrupted, h.publicKey); err == nil {
		t.Fatal("genesis not interrupted")
	}
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	key, err := format.MetadataPartKey(txn.Metadata.Manifest.Parts[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = run.close()
	if err := os.WriteFile(filepath.Join(h.serverRoot, filepath.FromSlash(key)), []byte("bad genesis bundle"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("corruption missed")
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("genesis ignored integrity incident")
	}
	if _, err := RepairMetadataEdge(ctx, h.options, "local", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
}

func TestForwardRepairRefusalDoesNotPublishWithoutAnIncident(t *testing.T) {
	h, part, base := incidentHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "git-push-intent-recorded" {
			return errors.New("interruption")
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); err == nil {
		t.Fatal("not interrupted")
	}
	if _, err := RepairDataPart(ctx, h.options, "local", part.PackHash, part.PartNumber); err == nil {
		t.Fatal("accepted forward repair without an incident")
	}
	remote := strings.TrimSpace(runGit(t, "--git-dir="+h.bare, "rev-parse", "refs/heads/main"))
	if remote != base {
		t.Fatalf("refused forward repair still published %s over %s", remote, base)
	}
}

func TestIntegrityIncidentRevokesMissingAcknowledgedPendingData(t *testing.T) {
	h, _, _ := incidentHarness(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(h.root, "new"), []byte("new data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "git-push-confirmed" {
			return errors.New("interruption")
		}
		return nil
	}
	if _, err := Commit(ctx, interrupted); err == nil {
		t.Fatal("not interrupted")
	}
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		t.Fatal(err)
	}
	part := packPartForIndexPath(t, candidate, "new")
	_ = run.close()
	if err := os.Remove(filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, "HEAD"); err == nil {
		t.Fatal("missing pending data was not detected")
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("acknowledged pending data loss was treated as ordinary mirror lag")
	}
}
