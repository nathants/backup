package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
	"github.com/nathants/go-libsodium"
)

func newFilesystemHarness(t *testing.T) (*integrationHarness, string) {
	t.Helper()
	libsodium.Init()
	public, secret, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	h := &integrationHarness{root: t.TempDir(), bare: filepath.Join(t.TempDir(), "metadata.git"), configPath: filepath.Join(t.TempDir(), "config"), serverRoot: t.TempDir(), publicKey: public, secretKey: secret}
	runGit(t, "init", "--bare", "--object-format=sha256", "--initial-branch=main", h.bare)
	identity, err := objectstore.InitializeFilesystem(h.serverRoot, "-")
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tfilesystem\t%s\t-\t-\t%s\t-\n", h.bare, identity, h.serverRoot)
	if err := os.WriteFile(h.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	h.options = Options{Root: h.root, ConfigPath: h.configPath, PackTarget: 1 << 20, PartSize: 1 << 20, MetadataPartSize: 1 << 20, SpaceReserveBytes: 1}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", secret))
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_FILE", "")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_CMD", "")
	// These must not affect a filesystem mirror or cause AWS credential loading.
	t.Setenv("AWS_ENDPOINT_URL", "http://invalid.example")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent"))
	return h, identity
}

func TestFilesystemBackupRestoreFullVerifyAndRecovery(t *testing.T) {
	h, identity := newFilesystemHarness(t)
	h.options.PartSize = 128
	ctx := context.Background()
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("some source data\n"), 400)
	for _, name := range []string{"file with spaces", "duplicate"} {
		if err := os.WriteFile(filepath.Join(h.root, name), data, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	timestamp := time.Unix(1670000000, 123456789)
	if err := os.Chtimes(filepath.Join(h.root, "file with spaces"), timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file with spaces", filepath.Join(h.root, "link")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := Add(ctx, h.options, false); err != nil {
			t.Fatal(err)
		}
	}
	first, err := Commit(ctx, h.options)
	if err != nil || strings.Join(first.CompleteMirrors, ",") != "local" {
		t.Fatalf("commit: %+v %v", first, err)
	}
	if _, err := Verify(ctx, h.options, 1, ""); err != nil {
		t.Fatal(err)
	}
	head, history := testReadHead(t, h.options)
	parts := 0
	if err := head.State.WalkPacks(format.DefaultLimits(), func(format.PackEntry) error { parts++; return nil }); err != nil {
		t.Fatal(err)
	}
	_ = history.Close()
	if parts < 2 {
		t.Fatal("split-pack fixture did not split")
	}
	full := h.options
	full.FullVerify = true
	if _, err := Verify(ctx, full, 1, ""); err != nil {
		t.Fatalf("full verify: %v", err)
	}
	target := t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: ".*", TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(target, "file with spaces"))
	if err != nil || !bytes.Equal(contents, data) {
		t.Fatalf("restore data: %v", err)
	}
	one, err := os.Stat(filepath.Join(target, "file with spaces"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := os.Stat(filepath.Join(target, "duplicate"))
	if err != nil {
		t.Fatal(err)
	}
	if one.Mode().Perm() != 0o640 || !one.ModTime().Equal(timestamp) || os.SameFile(one, two) {
		t.Fatalf("restore fidelity: %v %v", one, two)
	}
	if link, err := os.Readlink(filepath.Join(target, "link")); err != nil || link != "file with spaces" {
		t.Fatalf("symlink: %q %v", link, err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "file with spaces"), []byte("second revision"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	second, err := Commit(ctx, h.options)
	if err != nil {
		t.Fatal(err)
	}
	// An explicit mount-path change retaining the store identity remains valid.
	relocated := h.serverRoot + "-moved"
	if err := os.Rename(h.serverRoot, relocated); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(relocated, h.serverRoot); err != nil {
			t.Error(err)
		}
	}()
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.ReplaceAll(config, []byte(h.serverRoot), []byte(relocated))
	if err := os.WriteFile(h.configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, full, 1, ""); err != nil {
		t.Fatalf("moved store: %v", err)
	}
	// Recovery must work with both primary and original metadata checkout absent.
	if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(h.root, ".backup"), filepath.Join(t.TempDir(), "metadata")); err != nil {
		t.Fatal(err)
	}
	for _, tip := range []string{first.CommitID, second.CommitID} {
		recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: tip, Destination: filepath.Join(t.TempDir(), "recovered.git")})
		if err != nil || recovered.RecoveredTip != tip {
			t.Fatalf("recover %s from %s: %+v %v", tip, identity, recovered, err)
		}
	}
}

func TestFilesystemPlanExclusionAndOldPlanRejection(t *testing.T) {
	h, identity := newFilesystemHarness(t)
	ctx := context.Background()
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(h.root, "mounted disk")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "old-backup"), []byte("do not capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "source"), []byte("yes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	// Destination configured only after the earlier add; reject before publishing genesis.
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = bytes.ReplaceAll(config, []byte(h.serverRoot), []byte(destination))
	if err := os.WriteFile(h.configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil || !strings.Contains(err.Error(), "run add again") {
		t.Fatalf("unsafe saved plan: %v", err)
	}
	if refs := runGit(t, "--git-dir", h.bare, "for-each-ref"); refs != "" {
		t.Fatalf("unsafe plan published genesis: %s", refs)
	}
	var diagnostics bytes.Buffer
	options := h.options
	options.Stderr = &diagnostics
	added, err := Add(ctx, options, false)
	if err != nil || added.Entries != 1 {
		t.Fatalf("exclusion add: %+v %v", added, err)
	}
	if !strings.Contains(diagnostics.String(), "filesystem-mirror-excluded") {
		t.Fatal("exclusion not reported")
	}
	// Replace the fixture directory with the initialized destination only after
	// the no-network planning assertions. No mount privileges are needed.
	if err := os.Remove(filepath.Join(destination, "old-backup")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.serverRoot, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 1, ""); err != nil {
		t.Fatal(err)
	}
	if identity == "" {
		t.Fatal("missing store identity")
	}
}

func TestFilesystemAddMirrorSyncRepairAndMissingDisk(t *testing.T) {
	h, identity := newFilesystemHarness(t)
	ctx := context.Background()
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "data"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	secondID, err := objectstore.InitializeFilesystem(destination, "-")
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, []byte(fmt.Sprintf("mirror\tsecond\tfilesystem\t%s\t-\t-\t%s\t-\n", secondID, destination))...)
	if err := os.WriteFile(h.configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	mirrors := fmt.Sprintf("local\tfilesystem\t%s\t-\t-\nsecond\tfilesystem\t%s\t-\t-\n", identity, secondID)
	if err := os.WriteFile(filepath.Join(h.root, ".backup", "mirrors.tsv"), []byte(mirrors), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	added, err := Commit(ctx, h.options)
	if err != nil || strings.Join(added.CompleteMirrors, ",") != "local" {
		t.Fatalf("add mirror: %+v %v", added, err)
	}
	if _, err := Sync(ctx, h.options, "local", "second", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, h.options, "local", "second", ""); err != nil {
		t.Fatalf("idempotent sync: %v", err)
	}
	if _, err := Verify(ctx, h.options, 2, ""); err != nil {
		t.Fatal(err)
	}
	state, history := testReadHead(t, h.options)
	defer func() { _ = history.Close() }()
	var part format.PackEntry
	if err := state.State.WalkPacks(format.DefaultLimits(), func(row format.PackEntry) error { part = row; return nil }); err != nil {
		t.Fatal(err)
	}
	key, err := format.ObjectKey(part.PartHash, part.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("corrupted disk object")
	if err := os.WriteFile(filepath.Join(h.serverRoot, key), corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 2, ""); err == nil {
		t.Fatal("corruption accepted")
	}
	repaired, err := RepairDataPart(ctx, h.options, "second", part.PackHash, part.PartNumber)
	if err != nil || repaired.NewObjectID == part.ObjectID {
		t.Fatalf("repair: %+v %v", repaired, err)
	}
	if data, err := os.ReadFile(filepath.Join(h.serverRoot, key)); err != nil || !bytes.Equal(data, corrupt) {
		t.Fatalf("old object mutated: %v", err)
	}
	if _, err := Verify(ctx, h.options, 2, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairMetadataEdge(ctx, h.options, "local", ""); err != nil {
		t.Fatalf("metadata repair: %v", err)
	}
	full := h.options
	full.FullVerify = true
	if _, err := Verify(ctx, full, 2, ""); err != nil {
		t.Fatalf("full verify mirrors: %v", err)
	}
	if err := os.Rename(h.serverRoot, h.serverRoot+"-offline"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(h.serverRoot+"-offline", h.serverRoot); err != nil {
			t.Error(err)
		}
	}()
	result, err := Verify(ctx, h.options, 1, "")
	if err != nil || result.Passed != 1 {
		t.Fatalf("unplugged mirror: %+v %v", result, err)
	}
	if _, err := os.Lstat(h.serverRoot); !os.IsNotExist(err) {
		t.Fatalf("missing disk path recreated: %v", err)
	}
}

func testReadHead(t *testing.T, options Options) (repository.ValidatedCommit, *repository.History) {
	t.Helper()
	history, err := (repository.Validator{Repo: options.repositoryPath(), Limits: format.DefaultLimits()}).ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	tip, err := history.Tip()
	if err != nil {
		_ = history.Close()
		t.Fatal(err)
	}
	return tip, history
}

func TestFilesystemSyncAcrossProtocolBackend(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	directory := t.TempDir()
	identity, err := objectstore.InitializeFilesystem(directory, "-")
	if err != nil {
		t.Fatal(err)
	}
	protocolFactory := h.options.ClientFactory
	h.options.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror) (objectstore.Store, error) {
		if mirror.Canonical.Kind == format.MirrorFilesystem {
			return objectstore.OpenFilesystem(mirror.Directory, mirror.Mount, mirror.Canonical.S3URL, 1)
		}
		return protocolFactory(ctx, mirror)
	}
	localRow := fmt.Sprintf("local\tfilesystem\t%s\t-\t-", identity)
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\t%s\t%s\t-\n", h.bare, localRow, directory)
	if err := os.WriteFile(h.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "data"), []byte("cross-backend payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	remoteRow := fmt.Sprintf("remote\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1", h.http.URL)
	config += fmt.Sprintf("mirror\t%s\t-\t-\n", remoteRow)
	if err := os.WriteFile(h.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, ".backup", "mirrors.tsv"), []byte(localRow+"\n"+remoteRow+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, h.options, "local", "remote", ""); err != nil {
		t.Fatalf("filesystem to protocol: %v", err)
	}
	if _, err := Sync(ctx, h.options, "remote", "local", ""); err != nil {
		t.Fatalf("protocol to filesystem: %v", err)
	}
	head, history := testReadHead(t, h.options)
	defer func() { _ = history.Close() }()
	if err := head.State.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		key, err := format.ObjectKey(part.PartHash, part.ObjectID)
		if err != nil {
			return err
		}
		disk, err := os.ReadFile(filepath.Join(directory, key))
		if err != nil {
			return err
		}
		remote, err := os.ReadFile(filepath.Join(h.serverRoot, key))
		if err != nil {
			return err
		}
		if !bytes.Equal(disk, remote) {
			return fmt.Errorf("sync changed ciphertext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, h.options, 2, ""); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemCommitResumesAfterMandatoryGitOutage(t *testing.T) {
	h, _ := newFilesystemHarness(t)
	ctx := context.Background()
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, "data"), []byte("resume"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil {
		t.Fatal("local disk substituted for mandatory Git publication")
	}
	if err := os.Rename(h.bare+"-offline", h.bare); err != nil {
		t.Fatal(err)
	}
	committed, err := Commit(ctx, h.options)
	if err != nil || len(committed.CompleteMirrors) != 1 {
		t.Fatalf("resume: %+v %v", committed, err)
	}
	full := h.options
	full.FullVerify = true
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", strings.Repeat("0", 64))
	if _, err := Verify(ctx, full, 1, ""); err == nil {
		t.Fatal("full verification accepted wrong secret")
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	if _, err := Verify(ctx, full, 1, ""); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemFullVerificationReportsActualCountBelowThreshold(t *testing.T) {
	h, _ := newFilesystemHarness(t)
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	options := h.options
	options.FullVerify = true
	result, err := Verify(ctx, options, 2, "")
	if err == nil || result.Passed != 1 || len(result.Mirrors) != 1 || !result.Mirrors[0].Complete {
		t.Fatalf("threshold failure lost actual audit results: %+v %v", result, err)
	}
}
