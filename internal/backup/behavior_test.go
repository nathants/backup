package backup

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
	"backup/internal/s3server"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestResetAbandonsAcceptedUnpublishedGenesis(t *testing.T) {
	harness := newIntegrationHarness(t)
	failed := false
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "local-commit-accepted" && !failed {
			failed = true
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if _, err := Init(context.Background(), options, InitRequest{RecoveryPublicKey: harness.publicKey}); err == nil || !strings.Contains(err.Error(), "local-commit-accepted") {
		t.Fatalf("genesis did not stop after local branch acceptance: %v", err)
	}
	txn := loadTestTransaction(t, harness.options)
	if !txn.LocalAccepted || txn.PushAttempted || txn.LocalCommit == "" {
		t.Fatalf("unexpected stopped genesis state: %#v", txn)
	}
	if err := Reset(harness.options); err != nil {
		t.Fatalf("reset accepted unpublished genesis: %v", err)
	}
	repo, err := repository.OpenManaged(filepath.Join(harness.root, ".backup"), harness.bare, "main")
	if err != nil {
		t.Fatal(err)
	}
	if head, exists, err := repo.HeadIfExists(); err != nil || exists {
		t.Fatalf("reset left genesis head %q (exists=%t err=%v)", head, exists, err)
	}
	for _, name := range repository.RequiredBlobNames {
		if _, err := os.Lstat(filepath.Join(harness.root, ".backup", name)); !os.IsNotExist(err) {
			t.Fatalf("reset left genesis worktree blob %q: %v", name, err)
		}
	}
	result, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil || !isCommitID(result.CommitID) {
		t.Fatalf("fresh genesis after reset=%#v err=%v", result, err)
	}
}

func TestSecretKeyFileIsPrivateBoundedAndNoFollow(t *testing.T) {
	keyText := strings.Repeat("a", 64) + "\n"
	valid := filepath.Join(t.TempDir(), "secret-key")
	if err := os.WriteFile(valid, []byte(keyText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("valid file", func(t *testing.T) {
		t.Setenv("BACKUP_SECRET_KEY", "")
		t.Setenv("BACKUP_SECRET_KEY_FILE", valid)
		key, err := (&runtime{}).secretKey()
		if err != nil || fmt.Sprintf("%x", key) != strings.TrimSpace(keyText) {
			t.Fatalf("secret key=%x err=%v", key, err)
		}
	})
	t.Run("environment takes precedence", func(t *testing.T) {
		t.Setenv("BACKUP_SECRET_KEY", strings.Repeat("b", 64))
		t.Setenv("BACKUP_SECRET_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
		key, err := (&runtime{}).secretKey()
		if err != nil || fmt.Sprintf("%x", key) != strings.Repeat("b", 64) {
			t.Fatalf("secret key=%x err=%v", key, err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "secret-link")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BACKUP_SECRET_KEY", "")
		t.Setenv("BACKUP_SECRET_KEY_FILE", link)
		if _, err := (&runtime{}).secretKey(); err == nil {
			t.Fatal("symlinked secret-key file was accepted")
		}
	})
	t.Run("unsafe mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret-key")
		if err := os.WriteFile(path, []byte(keyText), 0o640); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BACKUP_SECRET_KEY", "")
		t.Setenv("BACKUP_SECRET_KEY_FILE", path)
		if _, err := (&runtime{}).secretKey(); err == nil {
			t.Fatal("group-readable secret-key file was accepted")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret-key")
		if err := os.WriteFile(path, []byte(strings.Repeat("a", maximumSecretKeyFileSize+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BACKUP_SECRET_KEY", "")
		t.Setenv("BACKUP_SECRET_KEY_FILE", path)
		if _, err := (&runtime{}).secretKey(); err == nil {
			t.Fatal("oversized secret-key file was accepted")
		}
	})
}

func TestRecoverWithWrongRecipientPublishesNothing(t *testing.T) {
	harness := newIntegrationHarness(t)
	genesis, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", strings.Repeat("0", 64))
	destination := filepath.Join(t.TempDir(), "recovered.git")
	_, err = Recover(context.Background(), harness.options, RecoverRequest{Mirror: "local", Tip: genesis.CommitID, Destination: destination})
	if err == nil || !strings.Contains(err.Error(), "no verified metadata chain") {
		t.Fatalf("wrong recovery recipient error=%v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("failed recovery published destination: %v", err)
	}
}

func TestEmptyAndDeletionSnapshotsRequireExplicitPermission(t *testing.T) {
	harness := newIntegrationHarness(t)
	configData, err := os.ReadFile(harness.configPath)
	if err != nil {
		t.Fatal(err)
	}
	externalConfig := filepath.Join(t.TempDir(), "backup-config")
	if err := os.WriteFile(externalConfig, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(harness.configPath); err != nil {
		t.Fatal(err)
	}
	harness.configPath = externalConfig
	harness.options.ConfigPath = externalConfig
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err == nil || !strings.Contains(err.Error(), "empty snapshot") {
		t.Fatalf("implicit empty snapshot was accepted: %v", err)
	}
	if result, err := Add(ctx, harness.options, true); err != nil || !result.NoChanges || result.Entries != 0 {
		t.Fatalf("explicit no-op empty snapshot: %#v %v", result, err)
	}

	path := filepath.Join(harness.root, "only-file")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	withFile, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err == nil || !strings.Contains(err.Error(), "empty snapshot") {
		t.Fatalf("implicit deletion-to-empty snapshot was accepted: %v", err)
	}
	staged, err := Add(ctx, harness.options, true)
	if err != nil || staged.NoChanges || staged.Entries != 0 {
		t.Fatalf("explicit deletion snapshot: %#v %v", staged, err)
	}
	var diffs []Diff
	_, err = DiffCandidate(harness.options, func(diff Diff) error {
		diffs = append(diffs, diff)
		return nil
	})
	if err != nil || len(diffs) != 1 || diffs[0].Kind != DiffDeletion || diffs[0].Old == nil || diffs[0].Old.Path != "./only-file" {
		t.Fatalf("deletion diff=%#v err=%v", diffs, err)
	}
	empty, err := Commit(ctx, harness.options)
	if err != nil || empty.CommitID == withFile.CommitID {
		t.Fatalf("commit deletion snapshot: %#v %v", empty, err)
	}
	entries, err := Find(harness.options, `^\./`, empty.CommitID, nil, nil)
	if err != nil || entries != 0 {
		t.Fatalf("empty committed snapshot entries=%d err=%v", entries, err)
	}
}

func TestRestoreOverwriteAndSymlinkConfinement(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(harness.root, "dir", "file")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("verified replacement"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))

	target := t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(target, "dir", "file")
	if err := os.WriteFile(destination, []byte("old bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./dir/file$`, Revision: snapshot.CommitID, TargetRoot: target, Overwrite: true}); err != nil {
		t.Fatalf("explicit regular-file overwrite: %v", err)
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "verified replacement" {
		t.Fatalf("overwritten bytes=%q err=%v", data, err)
	}

	outside := t.TempDir()
	unsafeTarget := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(unsafeTarget, "dir")); err != nil {
		t.Fatal(err)
	}
	for _, overwrite := range []bool{false, true} {
		if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./dir/file$`, Revision: snapshot.CommitID, TargetRoot: unsafeTarget, Overwrite: overwrite}); err == nil {
			t.Fatalf("restore followed destination parent symlink with overwrite=%t", overwrite)
		}
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("restore escaped through parent symlink: entries=%v err=%v", entries, err)
	}

	conflictTarget := t.TempDir()
	if err := os.MkdirAll(filepath.Join(conflictTarget, "dir", "file"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./dir/file$`, Revision: snapshot.CommitID, TargetRoot: conflictTarget, Overwrite: true}); err == nil || !strings.Contains(err.Error(), "destination conflicts") {
		t.Fatalf("overwrite replaced an incompatible destination directory: %v", err)
	}
	if info, err := os.Stat(filepath.Join(conflictTarget, "dir", "file")); err != nil || !info.IsDir() {
		t.Fatalf("incompatible destination changed: info=%#v err=%v", info, err)
	}

	rootLink := filepath.Join(t.TempDir(), "target-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./dir/file$`, Revision: snapshot.CommitID, TargetRoot: rootLink, Overwrite: true}); err == nil {
		t.Fatal("restore followed a symlinked target root")
	}
}

func TestRestoreDoesNotImplicitlyIncludeSymlinkTarget(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "target"), []byte("target payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(harness.root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(harness.root, "root-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", "")
	target := t.TempDir()
	result, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./link$`, Revision: latest.CommitID, TargetRoot: target})
	if err != nil || result.Published != 1 {
		t.Fatalf("symlink-only restore=%#v err=%v", result, err)
	}
	if link, err := os.Readlink(filepath.Join(target, "link")); err != nil || link != "target" {
		t.Fatalf("restored link=%q err=%v", link, err)
	}
	if _, err := os.Lstat(filepath.Join(target, "target")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was implicitly restored: %v", err)
	}
	rootTarget := t.TempDir()
	rootResult, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./root-link$`, Revision: latest.CommitID, TargetRoot: rootTarget})
	if err != nil || rootResult.Published != 1 {
		t.Fatalf("root-symlink restore=%#v err=%v", rootResult, err)
	}
	if link, err := os.Readlink(filepath.Join(rootTarget, "root-link")); err != nil || link != "." {
		t.Fatalf("restored root link=%q err=%v", link, err)
	}
}

func TestHistoricalRestoreReportsAndUsesExplicitRelocation(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("historical payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(snapshot.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	state := testHistoryTip(t, history).State
	fileHash, packHash := "", ""
	for _, entry := range testIndexEntries(t, state) {
		if entry.Path == "./file" {
			fileHash = strings.TrimPrefix(entry.Ref, "blake2b:")
			break
		}
	}
	for _, object := range testObjectEntries(t, state) {
		if object.PlaintextHash == fileHash {
			packHash = object.PackHash
			break
		}
	}
	var oldPart format.PackEntry
	for _, part := range testPackEntries(t, state) {
		if part.PackHash == packHash && part.PartNumber == 0 {
			oldPart = part
			break
		}
	}
	if fileHash == "" || packHash == "" || oldPart.PackHash == "" {
		t.Fatalf("could not resolve historical file pack: file=%q pack=%q part=%#v", fileHash, packHash, oldPart)
	}
	relocated, err := RepairDataPart(ctx, harness.options, "local", oldPart.PackHash, oldPart.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(harness.serverRoot, "objects", oldPart.PartHash, relocated.NewObjectID)
	offlineNewPath := newPath + ".temporarily-offline"
	if err := os.Rename(newPath, offlineNewPath); err != nil {
		t.Fatal(err)
	}
	pinnedTarget := t.TempDir()
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, TargetRoot: pinnedTarget}); err != nil {
		t.Fatalf("default historical restore did not remain pinned to its snapshot catalog: %v", err)
	}
	if err := os.Rename(offlineNewPath, newPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", strings.Repeat("0", 64))
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, TargetRoot: t.TempDir()}); err == nil || strings.Contains(err.Error(), "compatible immutable relocation") {
		t.Fatalf("authenticated-content failure incorrectly suggested relocation: %v", err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	oldPath := filepath.Join(harness.serverRoot, "objects", oldPart.PartHash, oldPart.ObjectID)
	corrupt, err := os.OpenFile(oldPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Write([]byte("corrupt historical representation")); err != nil {
		corrupt.Close()
		t.Fatal(err)
	}
	if err := corrupt.Close(); err != nil {
		t.Fatal(err)
	}
	dry, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, TargetRoot: t.TempDir(), DryRun: true})
	if err != nil || dry.Planned != 1 || dry.Published != 0 {
		t.Fatalf("dry run read corrupt historical object: %#v %v", dry, err)
	}
	_, err = Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, TargetRoot: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "compatible immutable relocation") || !strings.Contains(err.Error(), relocated.CommitID) {
		t.Fatalf("historical restore did not report the validated relocation: %v", err)
	}
	target := t.TempDir()
	result, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, CatalogRevision: relocated.CommitID, TargetRoot: target})
	if err != nil || result.SnapshotCommit != snapshot.CommitID || result.CatalogCommit != relocated.CommitID {
		t.Fatalf("explicit relocated historical restore: %#v %v", result, err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "file")); err != nil || string(data) != "historical payload" {
		t.Fatalf("relocated restore bytes=%q err=%v", data, err)
	}
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: snapshot.CommitID, CatalogRevision: genesis.CommitID, TargetRoot: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "descendant") {
		t.Fatalf("ancestor catalog was accepted: %v", err)
	}
}

func TestHistoricalRestoreDoesNotSuggestUnrelatedRelocation(t *testing.T) {
	harness := newIntegrationHarness(t)
	harness.options.PackTarget = 1
	harness.options.PartSize = 1 << 20
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"selected", "unrelated"} {
		if err := os.WriteFile(filepath.Join(harness.root, name), []byte("distinct payload for "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(snapshot.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	state := testHistoryTip(t, history).State
	selectedPart := packPartForIndexPath(t, state, "selected")
	unrelatedPart := packPartForIndexPath(t, state, "unrelated")
	if selectedPart.PackHash == unrelatedPart.PackHash {
		t.Fatal("test files unexpectedly shared a logical pack")
	}
	if _, err := RepairDataPart(ctx, harness.options, "local", unrelatedPart.PackHash, unrelatedPart.PartNumber); err != nil {
		t.Fatal(err)
	}
	selectedObject := filepath.Join(harness.serverRoot, "objects", selectedPart.PartHash, selectedPart.ObjectID)
	if err := os.WriteFile(selectedObject, []byte("corrupt selected historical representation"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	_, err = Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./selected$`, Revision: snapshot.CommitID, TargetRoot: t.TempDir()})
	if err == nil {
		t.Fatal("restore accepted corrupt selected ciphertext")
	}
	if strings.Contains(err.Error(), "compatible immutable relocation") {
		t.Fatalf("unrelated relocation was suggested for the unavailable selected part: %v", err)
	}
}

func TestHistoricalRestoreDoesNotSuggestSupersededRelocation(t *testing.T) {
	harness := newIntegrationHarness(t)
	harness.options.PackTarget = 1
	harness.options.PartSize = 1 << 20
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"selected", "unrelated"} {
		if err := os.WriteFile(filepath.Join(harness.root, name), []byte("superseded relocation payload for "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(snapshot.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	state := testHistoryTip(t, history).State
	selectedPart := packPartForIndexPath(t, state, "selected")
	unrelatedPart := packPartForIndexPath(t, state, "unrelated")
	firstRelocation, err := RepairDataPart(ctx, harness.options, "local", selectedPart.PackHash, selectedPart.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RepairDataPart(ctx, harness.options, "local", unrelatedPart.PackHash, unrelatedPart.PartNumber); err != nil {
		t.Fatal(err)
	}
	firstRelocatedPath := filepath.Join(harness.serverRoot, "objects", selectedPart.PartHash, firstRelocation.NewObjectID)
	if err := os.WriteFile(firstRelocatedPath, []byte("corrupt superseded relocation"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	_, err = Restore(ctx, harness.options, RestoreRequest{
		Pattern: `^\./selected$`, Revision: snapshot.CommitID, CatalogRevision: firstRelocation.CommitID, TargetRoot: t.TempDir(),
	})
	if err == nil {
		t.Fatal("restore accepted corrupt superseded relocation")
	}
	if strings.Contains(err.Error(), "compatible immutable relocation") {
		t.Fatalf("HEAD was suggested even though it retained the failed part mapping: %v", err)
	}
}

func packPartForIndexPath(t *testing.T, state repository.State, path string) format.PackEntry {
	t.Helper()
	plaintextHash := ""
	for _, entry := range testIndexEntries(t, state) {
		if entry.Path == "./"+path {
			plaintextHash = strings.TrimPrefix(entry.Ref, "blake2b:")
			break
		}
	}
	packHash := ""
	for _, object := range testObjectEntries(t, state) {
		if object.PlaintextHash == plaintextHash {
			packHash = object.PackHash
			break
		}
	}
	for _, part := range testPackEntries(t, state) {
		if part.PackHash == packHash && part.PartNumber == 0 {
			return part
		}
	}
	t.Fatalf("could not resolve pack part for %q", path)
	return format.PackEntry{}
}

type requestObservation struct {
	method   string
	path     string
	rawQuery string
}

type observingTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	seen []requestObservation
}

func (transport *observingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.seen = append(transport.seen, requestObservation{method: request.Method, path: request.URL.Path, rawQuery: request.URL.RawQuery})
	transport.mu.Unlock()
	return transport.base.RoundTrip(request)
}

func (transport *observingTransport) observations() []requestObservation {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]requestObservation(nil), transport.seen...)
}

func TestSyncCopiesCompleteRevisionIdempotentlyAndNeverTrustsConflict(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("sync payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err != nil {
		t.Fatal(err)
	}

	destinationRoot := t.TempDir()
	destinationServer, err := s3server.Open(s3server.Config{
		Root: destinationRoot, Bucket: "backup-destination", Prefix: "repository", Region: "us-east-1",
		Credentials: map[string]s3server.Credential{
			"writer": {SecretKey: "writer-secret", Role: s3server.RoleWriter},
			"reader": {SecretKey: "reader-secret", Role: s3server.RoleReader},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationHTTP := httptest.NewTLSServer(destinationServer)
	t.Cleanup(func() {
		destinationHTTP.Close()
		if err := destinationServer.Close(); err != nil {
			t.Errorf("close destination object server: %v", err)
		}
	})

	localRow := fmt.Sprintf("local\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\n", harness.http.URL)
	destinationRow := fmt.Sprintf("destination\tbackup-server\ts3://backup-destination/repository\t%s\tus-east-1\n", destinationHTTP.URL)
	if err := os.WriteFile(filepath.Join(harness.root, ".backup", "mirrors.tsv"), []byte(destinationRow+localRow), 0o644); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tdestination\tbackup-server\ts3://backup-destination/repository\t%s\tus-east-1\t-\t-\t-\nmirror\tlocal\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\t-\n", harness.bare, destinationHTTP.URL, harness.http.URL)
	if err := os.WriteFile(harness.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	actualFactory := func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		httpClient := harness.http.Client()
		if mirror.Canonical.Name == "destination" {
			httpClient = destinationHTTP.Client()
		}
		access, secret := "writer", "writer-secret"
		if role == objectstore.RoleReader {
			access, secret = "reader", "reader-secret"
		}
		return objectstore.New(ctx, objectstore.Options{
			Mirror: mirror.Canonical, Role: role,
			CredentialsProvider: credentials.NewStaticCredentialsProvider(access, secret, ""),
			HTTPClient:          httpClient,
		})
	}
	actualOptions := harness.options
	actualOptions.ClientFactory = actualFactory
	if _, err := Add(ctx, actualOptions, false); err != nil {
		t.Fatal(err)
	}
	offlineOptions := actualOptions
	offlineOptions.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		if mirror.Canonical.Name == "destination" {
			return nil, fmt.Errorf("destination intentionally unavailable")
		}
		return actualFactory(ctx, mirror, role)
	}
	latest, err := Commit(ctx, offlineOptions)
	if err != nil || strings.Join(latest.CompleteMirrors, ",") != "local" || strings.Join(latest.LaggingMirrors, ",") != "destination" {
		t.Fatalf("commit with lagging destination: %#v %v", latest, err)
	}

	constrained := actualOptions
	constrained.SpaceReserveBytes = ^uint64(0)
	if _, err := Sync(ctx, constrained, "local", "destination", latest.CommitID); err == nil || !strings.Contains(err.Error(), "stage sync object") {
		t.Fatalf("sync ignored impossible workspace reserve: %v", err)
	}
	synced, err := Sync(ctx, actualOptions, "local", "destination", latest.CommitID)
	if err != nil || synced.CommitID != latest.CommitID || synced.DataCopied == 0 || synced.MetadataCopied == 0 {
		t.Fatalf("sync result=%#v err=%v", synced, err)
	}
	verified, err := Verify(ctx, actualOptions, 2, latest.CommitID)
	if err != nil || verified.Passed != 2 {
		t.Fatalf("two-mirror verification=%#v err=%v", verified, err)
	}
	again, err := Sync(ctx, actualOptions, "local", "destination", latest.CommitID)
	if err != nil || again.DataCopied != 0 || again.MetadataCopied != 0 {
		t.Fatalf("idempotent sync=%#v err=%v", again, err)
	}

	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	part := testPackEntries(t, testHistoryTip(t, history).State)[0]
	corruptPath := filepath.Join(destinationRoot, "objects", part.PartHash, part.ObjectID)
	if err := os.WriteFile(corruptPath, []byte("corrupt immutable destination bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, actualOptions, "local", "destination", latest.CommitID); err == nil {
		t.Fatal("sync trusted or overwrote an existing corrupt destination object")
	}
	if data, err := os.ReadFile(corruptPath); err != nil || string(data) != "corrupt immutable destination bytes" {
		t.Fatalf("sync changed existing corrupt destination bytes: data=%q err=%v", data, err)
	}
}

func TestLargeFileStreamsAcrossMultipleCiphertextParts(t *testing.T) {
	harness := newIntegrationHarness(t)
	harness.options.PackTarget = 1 << 20
	harness.options.PartSize = 1 << 20
	harness.options.MetadataPartSize = 1 << 20
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(harness.root, "large")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(file, rand.Reader, 8<<20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	state := testHistoryTip(t, history).State
	var largePackParts []format.PackEntry
	for _, object := range testObjectEntries(t, state) {
		if object.PlaintextSize == 8<<20 {
			for _, part := range testPackEntries(t, state) {
				if part.PackHash == object.PackHash {
					largePackParts = append(largePackParts, part)
				}
			}
			break
		}
	}
	if len(largePackParts) < 2 || largePackParts[0].PartCount != uint32(len(largePackParts)) {
		t.Fatalf("large encrypted pack was not split into multiple ordinary objects: %#v", largePackParts)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	target := t.TempDir()
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./large$`, Revision: latest.CommitID, TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	hashFile := func(path string) objectstore.Object {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		identity, err := objectstore.HashReader(file)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	if source, restored := hashFile(path), hashFile(filepath.Join(target, "large")); source != restored {
		t.Fatalf("large restore identity mismatch: source=%#v restored=%#v", source, restored)
	}
}

func TestRestoreLatePublicationFailureReportsExactSubset(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(harness.root, name), []byte("payload "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	prior := syncPublishedParent
	calls := 0
	syncPublishedParent = func(int) error {
		calls++
		if calls == 1 {
			return fmt.Errorf("injected directory fsync failure")
		}
		return nil
	}
	defer func() { syncPublishedParent = prior }()
	target := t.TempDir()
	var published, remaining []string
	request := RestoreRequest{Pattern: `^\./[ab]$`, Revision: latest.CommitID, TargetRoot: target}
	request.Report = func(event RestoreEvent) error {
		switch event.Kind {
		case RestorePublished:
			published = append(published, event.Path)
		case RestoreRemaining:
			remaining = append(remaining, event.Path)
		}
		return nil
	}
	result, err := Restore(ctx, harness.options, request)
	if err == nil || result.Published != 1 || result.Remaining != 1 || strings.Join(published, ",") != "./a" || strings.Join(remaining, ",") != "./b" {
		t.Fatalf("publication result=%#v published=%v remaining=%v err=%v", result, published, remaining, err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "a")); err != nil || string(data) != "payload a" {
		t.Fatalf("published file is not complete: data=%q err=%v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(target, "b")); !os.IsNotExist(err) {
		t.Fatalf("remaining file was published: %v", err)
	}
}

func TestVerifyReportsEveryMirrorWhenThresholdPasses(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(harness.root, ".backup", "mirrors.tsv")
	localRow := fmt.Sprintf("local\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\n", harness.http.URL)
	offlineRow := "offline\tbackup-server\ts3://backup-offline/repository\thttps://127.0.0.1:1\tus-east-1\n"
	if err := os.WriteFile(metadataPath, []byte(localRow+offlineRow), 0o644); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\t-\nmirror\toffline\tbackup-server\ts3://backup-offline/repository\thttps://127.0.0.1:1\tus-east-1\t-\t-\t-\n", harness.bare, harness.http.URL)
	if err := os.WriteFile(harness.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	originalFactory := harness.options.ClientFactory
	harness.options.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		if mirror.Canonical.Name == "offline" {
			return nil, fmt.Errorf("offline mirror is unavailable")
		}
		return originalFactory(ctx, mirror, role)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(ctx, harness.options, 1, latest.CommitID)
	if err != nil || result.Passed != 1 || len(result.Mirrors) != 2 {
		t.Fatalf("threshold verification=%#v err=%v", result, err)
	}
	if result.Mirrors[0].Name != "local" || !result.Mirrors[0].Complete || result.Mirrors[1].Name != "offline" || result.Mirrors[1].Complete || result.Mirrors[1].Error == "" {
		t.Fatalf("verification did not report every mirror: %#v", result.Mirrors)
	}
}

func TestVerifyGetsOnlyBoundedPlaintextManifests(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}

	observer := &observingTransport{base: harness.http.Client().Transport}
	options := harness.options
	options.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		access, secret := "writer", "writer-secret"
		httpClient := harness.http.Client()
		if role == objectstore.RoleReader {
			access, secret = "reader", "reader-secret"
			clone := *httpClient
			clone.Transport = observer
			httpClient = &clone
		}
		return objectstore.New(ctx, objectstore.Options{
			Mirror: mirror.Canonical, Role: role,
			CredentialsProvider: credentials.NewStaticCredentialsProvider(access, secret, ""),
			HTTPClient:          httpClient,
		})
	}
	if _, err := Verify(ctx, options, 1, latest.CommitID); err != nil {
		t.Fatal(err)
	}
	seenGetManifest, seenHeadData, seenHeadBundlePart := false, false, false
	for _, request := range observer.observations() {
		switch {
		case request.method == http.MethodGet && strings.Contains(request.path, "/metadata/manifests/"):
			seenGetManifest = true
		case request.method == http.MethodGet && strings.Contains(request.rawQuery, "list-type=2"):
			// S3 listing is metadata discovery, not an object-body fetch.
		case request.method == http.MethodGet:
			t.Fatalf("verification fetched a pack or encrypted bundle body: %s?%s", request.path, request.rawQuery)
		case request.method == http.MethodHead && strings.Contains(request.path, "/objects/"):
			seenHeadData = true
		case request.method == http.MethodHead && strings.Contains(request.path, "/metadata/parts/"):
			seenHeadBundlePart = true
		}
	}
	if !seenGetManifest || !seenHeadData || !seenHeadBundlePart {
		t.Fatalf("verification request coverage: manifest GET=%t data HEAD=%t bundle-part HEAD=%t observations=%#v", seenGetManifest, seenHeadData, seenHeadBundlePart, observer.observations())
	}
}
