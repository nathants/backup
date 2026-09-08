package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/metadatachain"
	"backup/internal/objectstore"
	"backup/internal/repository"
	"backup/internal/s3server"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

type integrationHarness struct {
	root       string
	bare       string
	configPath string
	server     *s3server.Server
	serverRoot string
	http       *httptest.Server
	options    Options
	publicKey  []byte
	secretKey  []byte
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bare := filepath.Join(t.TempDir(), "metadata.git")
	runGit(t, "init", "--bare", "--object-format=sha256", "--initial-branch=main", bare)
	serverRoot := t.TempDir()
	server, err := s3server.Open(s3server.Config{
		Root: serverRoot, Bucket: "backup-test", Prefix: "repository", Region: "us-east-1",
		Credentials: map[string]s3server.Credential{
			"writer": {SecretKey: "writer-secret", Role: s3server.RoleWriter},
			"reader": {SecretKey: "reader-secret", Role: s3server.RoleReader},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server)
	t.Cleanup(func() {
		httpServer.Close()
		if err := server.Close(); err != nil {
			t.Errorf("close object server: %v", err)
		}
	})
	configPath := filepath.Join(root, ".backup-config")
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\t-\n", bare, httpServer.URL)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		access, secret := "writer", "writer-secret"
		if role == objectstore.RoleReader {
			access, secret = "reader", "reader-secret"
		}
		return objectstore.New(ctx, objectstore.Options{
			Mirror: mirror.Canonical, Role: role,
			CredentialsProvider: credentials.NewStaticCredentialsProvider(access, secret, ""),
			HTTPClient:          httpServer.Client(),
		})
	}
	return &integrationHarness{
		root: root, bare: bare, configPath: configPath, server: server, serverRoot: serverRoot, http: httpServer,
		options:   Options{Root: root, ConfigPath: configPath, PackTarget: 8, PartSize: 128, MetadataPartSize: 128, ClientFactory: factory},
		publicKey: publicKey, secretKey: secretKey,
	}
}

func TestInitAddDiffCommitAndNoOp(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	initResult, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if !isCommitID(initResult.CommitID) || strings.Join(initResult.CompleteMirrors, ",") != "local" {
		t.Fatalf("init result: %#v", initResult)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "alpha"), []byte("alpha"), 0o640); err != nil {
		t.Fatal(err)
	}
	addResult, err := Add(ctx, harness.options, false)
	if err != nil {
		t.Fatal(err)
	}
	if addResult.NoChanges || addResult.UniqueNewObjects == 0 {
		t.Fatalf("add result: %#v", addResult)
	}
	var diffs []Diff
	_, err = DiffCandidate(harness.options, func(diff Diff) error {
		diffs = append(diffs, diff)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, diff := range diffs {
		if diff.New != nil && diff.New.Path == "./alpha" && diff.Kind == DiffAddition {
			found = true
		}
	}
	if !found {
		t.Fatalf("alpha addition absent from diffs: %#v", diffs)
	}
	commitResult, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	if commitResult.CommitID == initResult.CommitID || strings.Join(commitResult.CompleteMirrors, ",") != "local" {
		t.Fatalf("commit result: %#v", commitResult)
	}
	addResult, err = Add(ctx, harness.options, false)
	if err != nil {
		t.Fatal(err)
	}
	if !addResult.NoChanges {
		t.Fatalf("unchanged scan staged a revision: %#v", addResult)
	}
	commitResult, err = Commit(ctx, harness.options)
	if err != nil || !commitResult.NoChanges || commitResult.CommitID == "" {
		t.Fatalf("no-op commit: %#v %v", commitResult, err)
	}
}

func TestMirrorTopologyCanBeAddedAndRemovedWithoutRebinding(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(harness.root, ".backup", "mirrors.tsv")
	localRow := fmt.Sprintf("local\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\n", harness.http.URL)
	newRow := "new\tbackup-server\ts3://backup-new/repository\thttps://new.example\tus-east-1\n"
	if err := os.WriteFile(metadataPath, []byte(localRow+newRow), 0o644); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\t-\nmirror\tnew\tbackup-server\ts3://backup-new/repository\thttps://new.example\tus-east-1\t-\t-\t-\n", harness.bare, harness.http.URL)
	if err := os.WriteFile(harness.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatalf("stage mirror addition: %v", err)
	}
	added, err := Commit(ctx, harness.options)
	if err != nil || strings.Join(added.CompleteMirrors, ",") != "local" {
		t.Fatalf("commit mirror addition: %#v %v", added, err)
	}

	if err := os.WriteFile(metadataPath, []byte(localRow), 0o644); err != nil {
		t.Fatal(err)
	}
	config = fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\t-\n", harness.bare, harness.http.URL)
	if err := os.WriteFile(harness.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatalf("stage mirror removal: %v", err)
	}
	removed, err := Commit(ctx, harness.options)
	if err != nil || strings.Join(removed.CompleteMirrors, ",") != "local" {
		t.Fatalf("commit mirror removal: %#v %v", removed, err)
	}
}

func TestVerifyAuditsDataAndMetadataChain(t *testing.T) {
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
	committed, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(ctx, harness.options, 1, committed.CommitID)
	if err != nil || verified.Passed != 1 || !verified.Mirrors[0].Complete {
		t.Fatalf("verification=%#v err=%v", verified, err)
	}
	if _, err := Verify(ctx, harness.options, 2, committed.CommitID); err == nil {
		t.Fatal("verification accepted an unmet mirror threshold")
	}
}

func TestRestoreVerifiesBeforePublicationAndPreservesMetadata(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(harness.root, "dir", "file")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := int64(1_700_000_000_123_456_789)
	stamp := time.Unix(0, mtime)
	if err := os.Chtimes(filePath, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir/file", filepath.Join(harness.root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	committed, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	target := t.TempDir()
	dry, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./(?:dir/file|link)$`, Revision: committed.CommitID, TargetRoot: target, DryRun: true})
	if err != nil || dry.Planned != 2 || dry.Published != 0 {
		t.Fatalf("dry run: %#v %v", dry, err)
	}
	result, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./(?:dir/file|link)$`, Revision: committed.CommitID, TargetRoot: target})
	if err != nil {
		t.Fatal(err)
	}
	if result.Published != 2 {
		t.Fatalf("restore result: %#v", result)
	}
	data, err := os.ReadFile(filepath.Join(target, "dir", "file"))
	if err != nil || string(data) != "payload" {
		t.Fatalf("restored data=%q err=%v", data, err)
	}
	info, err := os.Stat(filepath.Join(target, "dir", "file"))
	if err != nil || info.Mode().Perm() != 0o640 || info.ModTime().UnixNano() != mtime {
		t.Fatalf("restored metadata=%#v err=%v", info, err)
	}
	link, err := os.Readlink(filepath.Join(target, "link"))
	if err != nil || link != "dir/file" {
		t.Fatalf("restored link=%q err=%v", link, err)
	}
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./dir/file$`, Revision: committed.CommitID, TargetRoot: target}); err == nil {
		t.Fatal("existing destination was overwritten without --overwrite")
	}
}

func TestRestoreFailurePublishesNothing(t *testing.T) {
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
	committed, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", strings.Repeat("0", 64))
	target := t.TempDir()
	if _, err := Restore(ctx, harness.options, RestoreRequest{Pattern: `^\./file$`, Revision: committed.CommitID, TargetRoot: target}); err == nil {
		t.Fatal("wrong recipient secret was accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("restore failure published output: %#v %v", entries, err)
	}
}

func TestRestorePublicationErrorReportsAlreadyRenamedPath(t *testing.T) {
	target := t.TempDir()
	targetFD, _, err := openTargetRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(targetFD) }()
	source := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := blake2b.Sum512([]byte("payload"))
	entry := format.IndexEntry{Path: "./file", Kind: format.KindFile, Ref: fmt.Sprintf("blake2b:%x", digest[:]), Size: 7, Mode: 0o600}
	prior := syncPublishedParent
	syncPublishedParent = func(int) error { return unix.EIO }
	defer func() { syncPublishedParent = prior }()
	err = publishRegular(targetFD, source, entry, false)
	var marker interface{ Published() bool }
	if !errors.As(err, &marker) || !marker.Published() {
		t.Fatalf("post-rename fsync failure did not report publication: %v", err)
	}
	if data, readErr := os.ReadFile(filepath.Join(target, "file")); readErr != nil || string(data) != "payload" {
		t.Fatalf("renamed path missing after fsync failure: %q %v", data, readErr)
	}
}

func TestRepairRelocatesDataWithoutOverwritingOldObject(t *testing.T) {
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
	before, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(before.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	var oldPart format.PackEntry
	if err := testHistoryTip(t, history).State.WalkPacks(format.DefaultLimits(), func(entry format.PackEntry) error {
		if oldPart.PackHash == "" {
			oldPart = entry
		}
		return nil
	}); err != nil || oldPart.PackHash == "" {
		t.Fatalf("read committed pack: %#v %v", oldPart, err)
	}
	oldPath := filepath.Join(harness.serverRoot, "objects", oldPart.PartHash, oldPart.ObjectID)
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal(err)
	}
	constrained := harness.options
	constrained.SpaceReserveBytes = ^uint64(0)
	if _, err := RepairDataPart(ctx, constrained, "local", oldPart.PackHash, oldPart.PartNumber); err == nil || !strings.Contains(err.Error(), "stage repair part") {
		t.Fatalf("data repair ignored impossible workspace reserve: %v", err)
	}
	repaired, err := RepairDataPart(ctx, harness.options, "local", oldPart.PackHash, oldPart.PartNumber)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.CommitID == before.CommitID || repaired.NewObjectID == oldPart.ObjectID {
		t.Fatalf("repair result: %#v", repaired)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("repair removed or overwrote old immutable object: %v", err)
	}
	newPath := filepath.Join(harness.serverRoot, "objects", oldPart.PartHash, repaired.NewObjectID)
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("relocated object missing: %v", err)
	}
	if _, err := Verify(ctx, harness.options, 1, repaired.CommitID); err != nil {
		t.Fatal(err)
	}
}

type trackedTestReadCloser struct {
	io.Reader
	close func() error
}

func (reader *trackedTestReadCloser) Close() error { return reader.close() }

func TestMetadataRepairReadsPartsWithOneOpenDescriptor(t *testing.T) {
	active, maximum := 0, 0
	reader := &serialFileReader{
		paths: []string{"one", "two", "three"},
		open: func(path string) (io.ReadCloser, error) {
			active++
			if active > maximum {
				maximum = active
			}
			return &trackedTestReadCloser{Reader: strings.NewReader(path), close: func() error {
				active--
				return nil
			}}, nil
		},
	}
	data, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read serial parts: %v %v", err, closeErr)
	}
	if string(data) != "onetwothree" || maximum != 1 || active != 0 {
		t.Fatalf("data=%q maximum-open=%d active=%d", data, maximum, active)
	}
}

func TestRepairMetadataEdgePublishesAlternateWithoutGitCommit(t *testing.T) {
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
	repoPath := filepath.Join(harness.root, ".backup")
	history, err := (repository.Validator{Repo: repoPath, Limits: format.DefaultLimits()}).ValidateHistory(latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	reader := testMirrorClient(t, ctx, harness, objectstore.RoleReader)
	before, err := listManifestRepresentations(ctx, reader, latest.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(before) != 1 {
		t.Fatalf("representations=%#v err=%v", before, err)
	}
	oldPart := before[0].Manifest.Parts[0]
	oldPath := filepath.Join(harness.serverRoot, "metadata", "parts", oldPart.Hash, oldPart.ObjectID)
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil || len(oldBytes) == 0 {
		t.Fatal(err)
	}
	oldBytes[0] ^= 0xff
	if err := os.WriteFile(oldPath, oldBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, harness.options, 1, latest.CommitID); err == nil {
		t.Fatal("verification accepted the corrupted only metadata representation")
	}

	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	constrained := harness.options
	constrained.SpaceReserveBytes = ^uint64(0)
	if _, err := RepairMetadataEdge(ctx, constrained, "local", latest.CommitID); err == nil || !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("metadata repair ignored impossible workspace reserve: %v", err)
	}
	repaired, err := RepairMetadataEdge(ctx, harness.options, "local", latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.TipCommit != latest.CommitID || repaired.ManifestObjectID == before[0].ObjectID {
		t.Fatalf("repair result=%#v", repaired)
	}
	head := strings.TrimSpace(runGit(t, "-C", repoPath, "rev-parse", "HEAD"))
	if head != latest.CommitID {
		t.Fatalf("metadata repair created a Git commit: %s != %s", head, latest.CommitID)
	}
	corruptBytes, err := os.ReadFile(oldPath)
	if err != nil || !bytes.Equal(corruptBytes, oldBytes) {
		t.Fatalf("metadata repair changed old immutable bytes: %v", err)
	}
	after, err := listManifestRepresentations(ctx, reader, latest.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(after) < 2 {
		t.Fatalf("alternate representation missing: %#v %v", after, err)
	}
	if _, err := Verify(ctx, harness.options, 1, latest.CommitID); err != nil {
		t.Fatalf("verification after metadata repair: %v", err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	if _, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: latest.CommitID, Destination: filepath.Join(t.TempDir(), "recovered.git")}); err != nil {
		t.Fatalf("recovery after metadata repair: %v", err)
	}
}

func TestRecoverReconstructsMetadataWithoutPrimaryRemote(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
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
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	latestDestination := filepath.Join(t.TempDir(), "latest.git")
	recovered, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: latest.CommitID, Destination: latestDestination})
	if err != nil || recovered.RecoveredTip != latest.CommitID {
		t.Fatalf("recover latest=%#v err=%v", recovered, err)
	}
	if got := strings.TrimSpace(runGit(t, "--git-dir", latestDestination, "rev-parse", "refs/backup/recovered-tip")); got != latest.CommitID {
		t.Fatalf("recovered latest tip=%s", got)
	}
	earlierDestination := filepath.Join(t.TempDir(), "earlier.git")
	recovered, err = Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: genesis.CommitID, Destination: earlierDestination})
	if err != nil || recovered.RecoveredTip != genesis.CommitID {
		t.Fatalf("recover earlier=%#v err=%v", recovered, err)
	}
}

func TestRecoverTriesAlternateLogicalPaths(t *testing.T) {
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
	reader := testMirrorClient(t, ctx, harness, objectstore.RoleReader)
	writer := testMirrorClient(t, ctx, harness, objectstore.RoleWriter)
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	representations, err := listManifestRepresentations(ctx, reader, latest.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(representations) != 1 {
		t.Fatalf("representations=%#v err=%v", representations, err)
	}
	valid := representations[0]
	manifest := cloneTestManifest(valid.Manifest)
	manifest.BaseCommit = strings.Repeat("f", 64)
	manifest.Parts[0].ObjectID = strings.Repeat("0", 32)
	uploadTestManifest(t, ctx, writer, manifest, strings.Repeat("1", 32))
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	destination := filepath.Join(t.TempDir(), "recovered.git")
	recovered, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: latest.CommitID, Destination: destination})
	if err != nil || recovered.RecoveredTip != latest.CommitID {
		t.Fatalf("healthy logical path was not tried: %#v %v", recovered, err)
	}
}

func TestRecoverIgnoresUnusableMaximalExtension(t *testing.T) {
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
	reader := testMirrorClient(t, ctx, harness, objectstore.RoleReader)
	writer := testMirrorClient(t, ctx, harness, objectstore.RoleWriter)
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(latest.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	representations, err := listManifestRepresentations(ctx, reader, latest.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(representations) != 1 {
		t.Fatalf("representations=%#v err=%v", representations, err)
	}
	fakeTip := strings.Repeat("f", 64)
	manifest := cloneTestManifest(representations[0].Manifest)
	manifest.Sequence++
	manifest.BaseCommit = latest.CommitID
	manifest.TipCommit = fakeTip
	manifest.Kind = format.BundleIncremental
	uploadTestManifest(t, ctx, writer, manifest, strings.Repeat("e", 32))

	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	destination := filepath.Join(t.TempDir(), "recovered.git")
	recovered, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Destination: destination})
	if err != nil || recovered.RecoveredTip != latest.CommitID {
		t.Fatalf("unusable extension hid the latest verified tip: %#v %v", recovered, err)
	}
}

func TestRecoverRequiresChoiceForVerifiedForks(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	mainTip, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	repoPath := filepath.Join(harness.root, ".backup")
	genesisHistory, err := (repository.Validator{Repo: repoPath, Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	blobs := testStateBlobs(t, testHistoryTip(t, genesisHistory).State)
	blobs["ignore"] = []byte("^\\./fork-only$\n")
	repo := &repository.Managed{Directory: repoPath}
	forkTip, err := repo.CreateCommit(genesis.CommitID, blobs, "test fork")
	if err != nil {
		t.Fatal(err)
	}
	writer := testMirrorClient(t, ctx, harness, objectstore.RoleWriter)
	uploadTestMetadataBundle(t, ctx, writer, repo, testHistoryGenesisFormat(t, genesisHistory).RepositoryUUID, genesis.CommitID, forkTip, 1, harness.publicKey, harness.options.MetadataPartSize)

	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	if _, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Destination: filepath.Join(t.TempDir(), "ambiguous.git")}); err == nil || !strings.Contains(err.Error(), "2 verified maximal tips") {
		t.Fatalf("verified fork was not reported: %v", err)
	}
	forkDestination := filepath.Join(t.TempDir(), "fork.git")
	recovered, err := Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: forkTip, Destination: forkDestination})
	if err != nil || recovered.RecoveredTip != forkTip {
		t.Fatalf("explicit fork recovery=%#v err=%v", recovered, err)
	}
	mainDestination := filepath.Join(t.TempDir(), "main.git")
	recovered, err = Recover(ctx, harness.options, RecoverRequest{Mirror: "local", Tip: mainTip.CommitID, Destination: mainDestination})
	if err != nil || recovered.RecoveredTip != mainTip.CommitID {
		t.Fatalf("explicit main recovery=%#v err=%v", recovered, err)
	}
}

func TestMetadataBundleRejectsUnreachableObjects(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "main"), []byte("main"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	latest, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	repo := &repository.Managed{Directory: filepath.Join(harness.root, ".backup")}
	stage := t.TempDir()
	fullBundle := filepath.Join(stage, "full.bundle")
	if err := repo.CreateBundle("", genesis.CommitID, fullBundle); err != nil {
		t.Fatal(err)
	}
	quarantinePath := filepath.Join(stage, "quarantine.git")
	quarantine, err := initializeMetadataQuarantine(quarantinePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyMetadataBundle(quarantine, fullBundle, format.MetadataManifest{Kind: format.BundleFull, BaseCommit: "-", TipCommit: genesis.CommitID}, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}

	maliciousBundle := filepath.Join(stage, "extra.bundle")
	data, extra := recoveryBundleWithExtraObject(t, repo, genesis.CommitID, latest.CommitID)
	if err := os.WriteFile(maliciousBundle, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := format.MetadataManifest{Kind: format.BundleIncremental, BaseCommit: genesis.CommitID, TipCommit: latest.CommitID}
	assertValidRecoveryBundleHeader(t, maliciousBundle, manifest)
	if err := applyMetadataBundle(quarantine, maliciousBundle, manifest, genesis.CommitID); err == nil || !strings.Contains(err.Error(), "outside its declared tip graph") {
		t.Fatalf("metadata bundle did not reach unreachable-object rejection: %v", err)
	}
	if _, err := quarantine.RunGit(nil, 1024, "cat-file", "-e", extra); err != nil {
		t.Fatalf("fixture's unreachable object was not imported: %v", err)
	}
}

func TestMetadataRecoveryTriesAlternatePhysicalRepresentations(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config, err := localconfig.Load(harness.configPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := harness.options.ClientFactory(ctx, config.Mirrors[0], objectstore.RoleReader)
	if err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	representations, err := listManifestRepresentations(ctx, reader, genesis.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(representations) != 1 {
		t.Fatalf("representations=%#v err=%v", representations, err)
	}
	valid := representations[0]
	bad := valid
	bad.Manifest.Parts = append([]format.ManifestPart(nil), valid.Manifest.Parts...)
	bad.Manifest.Parts[0].ObjectID = strings.Repeat("0", 32)

	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(root, "recovered.git")
	if _, err := materializeMetadataChain(ctx, reader, [][]manifestRepresentation{{bad, valid}}, harness.secretKey, quarantine, stage); err != nil {
		t.Fatalf("healthy alternate was not tried: %v", err)
	}
	resolved := strings.TrimSpace(runGit(t, "--git-dir", quarantine, "rev-parse", "refs/backup/recovered-tip"))
	if resolved != genesis.CommitID {
		t.Fatalf("recovered tip=%s", resolved)
	}
}

func TestMetadataRecoveryTriesAlternativeAfterDeclaredTipMismatch(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	repoPath := filepath.Join(harness.root, ".backup")
	history, err := (repository.Validator{Repo: repoPath, Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	reader := testMirrorClient(t, ctx, harness, objectstore.RoleReader)
	writer := testMirrorClient(t, ctx, harness, objectstore.RoleWriter)
	valid, err := listManifestRepresentations(ctx, reader, genesis.CommitID, testHistoryGenesisFormat(t, history).RepositoryUUID)
	if err != nil || len(valid) != 1 {
		t.Fatalf("representations=%#v err=%v", valid, err)
	}
	blobs := testStateBlobs(t, testHistoryTip(t, history).State)
	blobs["ignore"] = []byte("fork\n")
	repo := &repository.Managed{Directory: repoPath}
	fork, err := repo.CreateCommit(genesis.CommitID, blobs, "failed alternate fork")
	if err != nil {
		t.Fatal(err)
	}
	bad := uploadTestMetadataBundle(t, ctx, writer, repo, testHistoryGenesisFormat(t, history).RepositoryUUID, "", fork, 0, harness.publicKey, harness.options.MetadataPartSize)
	// The ciphertext is a valid full bundle for fork, but its completion marker
	// claims genesis. Header validation rejects this before importing objects;
	// actual post-import cleanup is covered by the unreachable-object fixture.
	bad.Manifest.TipCommit = genesis.CommitID

	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(root, "recovered.git")
	if _, err := materializeMetadataChain(ctx, reader, [][]manifestRepresentation{{bad, valid[0]}}, harness.secretKey, quarantine, stage); err != nil {
		t.Fatalf("declared-tip mismatch prevented the healthy retry: %v", err)
	}
}

func TestWorkspaceCapacityRejectsInsufficientAndOverflowingBudgets(t *testing.T) {
	directory := t.TempDir()
	available, _, err := filesystem.DirectoryCapacity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireWorkspaceCapacity(directory, 1, 1, available); err == nil || !strings.Contains(err.Error(), "reserve") {
		t.Fatalf("insufficient workspace was accepted: %v", err)
	}
	if err := requireWorkspaceCapacity(directory, ^uint64(0), 1, 1); err == nil || !strings.Contains(err.Error(), "needs") {
		t.Fatalf("overflowing workspace request was accepted: %v", err)
	}
}

func TestRestoreLowSpaceFailsBeforePublication(t *testing.T) {
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
	committed, err := Commit(ctx, harness.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	target := t.TempDir()
	options := harness.options
	options.SpaceReserveBytes = ^uint64(0)
	if _, err := Restore(ctx, options, RestoreRequest{Pattern: `^\./file$`, Revision: committed.CommitID, TargetRoot: target}); err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("restore ignored impossible workspace reserve: %v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("low-space restore published paths: %#v %v", entries, err)
	}
}

func TestRecoverLowSpaceFailsBeforeDestinationPublication(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	destination := filepath.Join(t.TempDir(), "recovered.git")
	options := harness.options
	options.SpaceReserveBytes = ^uint64(0)
	if _, err := Recover(ctx, options, RecoverRequest{Mirror: "local", Tip: genesis.CommitID, Destination: destination}); err == nil || !strings.Contains(err.Error(), "recovery verification workspace") {
		t.Fatalf("recover ignored impossible workspace reserve: %v", err)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("low-space recovery published a destination: %v", err)
	}
}

func TestAddRejectsOversizedMutableConfigurationBeforeAllocation(t *testing.T) {
	harness := newIntegrationHarness(t)
	if _, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(harness.root, ".backup", "ignore")
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(format.MaximumIgnoreBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(context.Background(), harness.options, false); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("oversized ignore configuration was accepted: %v", err)
	}
}

type diagnosticErrorWriter struct{}

func (diagnosticErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestAddPropagatesMandatoryDiagnosticWriteFailure(t *testing.T) {
	harness := newIntegrationHarness(t)
	if _, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(harness.root, "special"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := harness.options
	options.Stderr = diagnosticErrorWriter{}
	if _, err := Add(context.Background(), options, false); err == nil || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("diagnostic output failure was ignored: %v", err)
	}
}

func TestRemoveTreeNoFollowRemovesNestedDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeNoFollow(root); err != nil {
		t.Fatalf("remove nested tree: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("tree still exists: %v", err)
	}
}

func TestInitRejectsMetadataRepositorySymlink(t *testing.T) {
	harness := newIntegrationHarness(t)
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(harness.root, ".backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err == nil {
		t.Fatal("metadata repository symlink was accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("initialization wrote through metadata repository symlink: %v", entries)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("metadata repository symlink target mode changed to %04o", info.Mode().Perm())
	}
}

func TestInitUsesRootLockBeforeCreatingRepository(t *testing.T) {
	harness := newIntegrationHarness(t)
	lock, err := acquireInitializationLock(harness.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err == nil || !strings.Contains(err.Error(), "initialization is in progress") {
		t.Fatalf("concurrent initialization was not rejected: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatalf("initialization did not proceed after releasing root lock: %v", err)
	}
}

func TestInitRecoversEmptyRepositoryCreatedBeforeGenesisIntent(t *testing.T) {
	harness := newIntegrationHarness(t)
	repositoryPath := filepath.Join(harness.root, ".backup")
	if _, err := repository.Initialize(repositoryPath, harness.bare, "main"); err != nil {
		t.Fatal(err)
	}
	result, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil || !isCommitID(result.CommitID) {
		t.Fatalf("init did not recover empty partial repository: %#v %v", result, err)
	}
	remote := strings.TrimSpace(runGit(t, "--git-dir", harness.bare, "rev-parse", "refs/heads/main"))
	if remote != result.CommitID {
		t.Fatalf("remote=%s result=%s", remote, result.CommitID)
	}
}

func TestInitIsResumableAndRefusesSecondGenesis(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	first, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err == nil || second.CommitID != "" {
		t.Fatalf("second genesis accepted: %#v %v", second, err)
	}
	remote := strings.TrimSpace(runGit(t, "--git-dir", harness.bare, "rev-parse", "refs/heads/main"))
	if remote != first.CommitID {
		t.Fatalf("remote=%s first=%s", remote, first.CommitID)
	}
}

func TestTransactionResumesAfterEveryDurableCheckpoint(t *testing.T) {
	points := []string{
		"commit-capture-started",
		"completed-pack-recorded",
		"commit-capture-finalized",
		"data-revision-acknowledged",
		"local-commit-recorded",
		"materialization-intent-recorded",
		"materialization-blob-FORMAT",
		"materialization-blob-index.tsv",
		"materialization-blob-objects.tsv",
		"materialization-blob-packs.tsv",
		"materialization-blob-ignore",
		"materialization-blob-.publickeys",
		"materialization-blob-mirrors.tsv",
		"materialization-ref-updated",
		"materialization-intent-cleared",
		"local-commit-accepted",
		"metadata-staged",
		"git-push-intent-recorded",
		"git-push-returned",
		"git-push-confirmed",
		"metadata-part-created-before-ack",
		"metadata-part-acknowledged",
		"metadata-manifest-created-before-ack",
		"completion-ledger-recorded",
		"mirror-revision-acknowledged",
		"transaction-control-cleared",
		"transaction-cleared",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			harness := newIntegrationHarness(t)
			ctx := context.Background()
			if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload for "+point), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, harness.options, false); err != nil {
				t.Fatal(err)
			}
			failed := false
			var observedPoints []string
			options := harness.options
			options.failurePoint = func(observed string) error {
				observedPoints = append(observedPoints, observed)
				if observed == point && !failed {
					failed = true
					return fmt.Errorf("simulated process stop")
				}
				return nil
			}
			if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "checkpoint "+point) {
				t.Fatalf("checkpoint %s did not stop commit: %v; observed %v", point, err, observedPoints)
			}
			if !failed {
				t.Fatalf("checkpoint %s was not reached", point)
			}
			result, err := Commit(ctx, harness.options)
			if err != nil {
				t.Fatalf("resume after %s: %v", point, err)
			}
			if !isCommitID(result.CommitID) {
				t.Fatalf("resume after %s returned invalid commit: %#v", point, result)
			}
			verified, err := Verify(ctx, harness.options, 1, result.CommitID)
			if err != nil || verified.Passed != 1 {
				t.Fatalf("verify after %s: %#v %v", point, verified, err)
			}
		})
	}
}

func TestAddAndGenesisResumeAfterDurableIntent(t *testing.T) {
	t.Run("genesis", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		failed := false
		options := harness.options
		options.failurePoint = func(point string) error {
			if point == "genesis-transaction-recorded" && !failed {
				failed = true
				return fmt.Errorf("simulated process stop")
			}
			return nil
		}
		if _, err := Init(context.Background(), options, InitRequest{RecoveryPublicKey: harness.publicKey}); err == nil {
			t.Fatal("genesis checkpoint did not stop initialization")
		}
		result, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
		if err != nil || !isCommitID(result.CommitID) {
			t.Fatalf("resume genesis: %#v %v", result, err)
		}
	})

	t.Run("candidate", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		failed := false
		options := harness.options
		options.failurePoint = func(point string) error {
			if point == "candidate-transaction-recorded" && !failed {
				failed = true
				return fmt.Errorf("simulated process stop")
			}
			return nil
		}
		if _, err := Add(ctx, options, false); err == nil {
			t.Fatal("candidate checkpoint did not stop add")
		}
		result, err := Commit(ctx, harness.options)
		if err != nil || !isCommitID(result.CommitID) {
			t.Fatalf("resume candidate: %#v %v", result, err)
		}
	})
}

func TestDeterministicMirrorUnavailabilityRetainsImmutableIdentities(t *testing.T) {
	t.Run("data", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("offline data payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		options := harness.options
		options.ClientFactory = func(context.Context, localconfig.Mirror, objectstore.Role) (*objectstore.Client, error) {
			return nil, fmt.Errorf("mirror is deterministically unavailable")
		}
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "no individual mirror acknowledged ciphertext part") {
			t.Fatalf("deterministic data unavailability was misclassified: %v", err)
		}
		after := loadTestTransaction(t, harness.options)
		if after.Capture == nil || after.Capture.NextPlan != 0 || len(after.CandidateFiles) != 0 {
			t.Fatalf("incomplete pack became durable progress: %#v", after.Capture)
		}
		if result, err := Commit(ctx, harness.options); err != nil || !isCommitID(result.CommitID) {
			t.Fatalf("retry after deterministic data outage: %#v %v", result, err)
		}
	})

	t.Run("metadata", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		if _, err := Commit(ctx, harness.options); err != nil {
			t.Fatal(err)
		}
		ignorePath := filepath.Join(harness.root, ".backup", "ignore")
		if err := os.WriteFile(ignorePath, []byte("^\\./never$\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		originalFactory := harness.options.ClientFactory
		options := harness.options
		options.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
			if role == objectstore.RoleWriter {
				return nil, fmt.Errorf("mirror is deterministically unavailable")
			}
			return originalFactory(ctx, mirror, role)
		}
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "no individual mirror has a complete metadata chain") || !strings.Contains(err.Error(), "mirror is deterministically unavailable") {
			t.Fatalf("deterministic metadata unavailability was misclassified: %v", err)
		}
		first := loadTestTransaction(t, harness.options)
		if first.Metadata == nil || !first.PushConfirmed {
			t.Fatalf("expected resumable post-push metadata staging, got %#v", first)
		}
		partID, manifestID := first.Metadata.Manifest.Parts[0].ObjectID, first.Metadata.ManifestObjectID
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "no individual mirror has a complete metadata chain") || !strings.Contains(err.Error(), "mirror is deterministically unavailable") {
			t.Fatalf("repeated deterministic metadata unavailability was misclassified: %v", err)
		}
		second := loadTestTransaction(t, harness.options)
		if second.Metadata.Manifest.Parts[0].ObjectID != partID || second.Metadata.ManifestObjectID != manifestID {
			t.Fatal("deterministic metadata failure changed immutable representation identity")
		}
	})
}

func TestUploadRelocationCheckpointsResumeAfterRestart(t *testing.T) {
	prepareRepair := func(t *testing.T) (*integrationHarness, format.PackEntry) {
		t.Helper()
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("repair checkpoint payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
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
		part := firstTestPackPart(t, testHistoryTip(t, history).State)
		return harness, part
	}
	for _, point := range []string{"data-object-created-before-ack", "data-object-acknowledged"} {
		t.Run(point, func(t *testing.T) {
			harness, part := prepareRepair(t)
			stopped := false
			options := harness.options
			options.failurePoint = func(observed string) error {
				if observed == point && !stopped {
					stopped = true
					return fmt.Errorf("simulated restart")
				}
				return nil
			}
			if _, err := RepairDataPart(context.Background(), options, "local", part.PackHash, part.PartNumber); err == nil {
				t.Fatalf("checkpoint %s did not stop repair", point)
			}
			if !stopped {
				t.Fatalf("checkpoint %s was not reached", point)
			}
			if _, err := Commit(context.Background(), harness.options); err != nil {
				t.Fatalf("resume after %s: %v", point, err)
			}
		})
	}
	t.Run("data-object-relocated", func(t *testing.T) {
		harness, part := prepareRepair(t)
		options := withWriterTransport(harness, func(base http.RoundTripper) http.RoundTripper {
			return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
				return request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/objects/")
			}}
		})
		stopped := false
		options.failurePoint = func(point string) error {
			if point == "data-object-relocated" && !stopped {
				stopped = true
				return fmt.Errorf("simulated restart")
			}
			return nil
		}
		if _, err := RepairDataPart(context.Background(), options, "local", part.PackHash, part.PartNumber); err == nil || !stopped {
			t.Fatalf("relocation checkpoint did not stop repair: %v", err)
		}
		if _, err := Commit(context.Background(), harness.options); err != nil {
			t.Fatalf("resume after data relocation: %v", err)
		}
	})
	t.Run("metadata-representation-relocated", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("metadata relocation checkpoint"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		options := withWriterTransport(harness, func(base http.RoundTripper) http.RoundTripper {
			return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
				return request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/metadata/parts/")
			}}
		})
		stopped := false
		options.failurePoint = func(point string) error {
			if point == "metadata-representation-relocated" && !stopped {
				stopped = true
				return fmt.Errorf("simulated restart")
			}
			return nil
		}
		if _, err := Commit(ctx, options); err == nil || !stopped {
			t.Fatalf("metadata relocation checkpoint did not stop commit: %v", err)
		}
		if _, err := Commit(ctx, harness.options); err != nil {
			t.Fatalf("resume after metadata relocation: %v", err)
		}
	})
}

func TestAmbiguousUploadsUseAuditOrFreshImmutableIdentity(t *testing.T) {
	t.Run("lost data response is audited", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		harness.options.PackTarget = 1 << 20
		harness.options.PartSize = 1 << 20
		harness.options.MetadataPartSize = 1 << 20
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("lost response payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		options := withWriterTransport(harness, func(base http.RoundTripper) http.RoundTripper {
			return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
				return request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/objects/")
			}, afterResponse: true}
		})
		result, err := Commit(ctx, options)
		if err != nil {
			t.Fatalf("audited lost response did not complete: %v", err)
		}
		history, err := (repository.Validator{Repo: filepath.Join(harness.root, ".backup"), Limits: format.DefaultLimits()}).ValidateHistory(result.CommitID)
		if err != nil {
			t.Fatal(err)
		}
		if testHistoryTip(t, history).State.PackCount == 0 {
			t.Fatal("audited lost response did not publish the captured pack")
		}
	})

	t.Run("unverifiable data ambiguity relocates before publication", func(t *testing.T) {
		harness := newIntegrationHarness(t)
		harness.options.PackTarget = 1 << 20
		harness.options.PartSize = 1 << 20
		harness.options.MetadataPartSize = 1 << 20
		ctx := context.Background()
		if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("ambiguous data payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, harness.options, false); err != nil {
			t.Fatal(err)
		}
		options := withWriterTransport(harness, func(base http.RoundTripper) http.RoundTripper {
			return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
				return request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/objects/")
			}}
		})
		if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "no individual mirror acknowledged ciphertext part") {
			t.Fatalf("unverifiable data ambiguity was not left as an incomplete pack: %v", err)
		}
		after := loadTestTransaction(t, harness.options)
		if after.Capture == nil || after.Capture.NextPlan != 0 || after.LocalCommit != "" {
			t.Fatalf("incomplete ambiguous pack became durable progress: %#v", after.Capture)
		}
		result, err := Commit(ctx, harness.options)
		if err != nil {
			t.Fatalf("commit after data relocation: %v", err)
		}
		if _, err := Verify(ctx, harness.options, 1, result.CommitID); err != nil {
			t.Fatal(err)
		}
	})

	for _, test := range []struct {
		name  string
		match string
	}{
		{name: "metadata part", match: "/metadata/parts/"},
		{name: "metadata manifest", match: "/metadata/manifests/"},
	} {
		t.Run(test.name+" ambiguity relocates", func(t *testing.T) {
			harness := newIntegrationHarness(t)
			harness.options.PackTarget = 1 << 20
			harness.options.PartSize = 1 << 20
			harness.options.MetadataPartSize = 1 << 20
			ctx := context.Background()
			if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("metadata ambiguity payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, harness.options, false); err != nil {
				t.Fatal(err)
			}
			var attempted []string
			options := withWriterTransport(harness, func(base http.RoundTripper) http.RoundTripper {
				return &faultRoundTripper{base: base, match: func(request *http.Request) bool {
					if request.Method == http.MethodPut && strings.Contains(request.URL.Path, test.match) {
						attempted = append(attempted, request.URL.Path)
						return true
					}
					return false
				}}
			})
			if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "ambiguous metadata uploads") {
				t.Fatalf("unverifiable metadata ambiguity did not rotate: %v", err)
			}
			if len(attempted) == 0 {
				t.Fatal("fault transport did not observe a metadata upload")
			}
			txn := loadTestTransaction(t, harness.options)
			if txn.Metadata == nil || !txn.PushConfirmed {
				t.Fatalf("metadata relocation did not preserve resumable post-push state: %#v", txn)
			}
			for _, path := range attempted {
				if strings.HasSuffix(path, "/"+txn.Metadata.ManifestObjectID) {
					t.Fatal("metadata manifest retained its unverifiable physical identity")
				}
				for _, part := range txn.Metadata.Manifest.Parts {
					if strings.HasSuffix(path, "/"+part.ObjectID) {
						t.Fatal("metadata part retained its unverifiable physical identity")
					}
				}
			}
			result, err := Commit(ctx, harness.options)
			if err != nil {
				t.Fatalf("commit after metadata relocation: %v", err)
			}
			if _, err := Verify(ctx, harness.options, 1, result.CommitID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func loadTestTransaction(t *testing.T, options Options) *transaction {
	t.Helper()
	run, err := openRuntime(options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil || txn == nil {
		t.Fatalf("load transaction: %#v %v", txn, err)
	}
	return txn
}

func captureTestTransaction(t *testing.T, harness *integrationHarness) {
	t.Helper()
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "commit-capture-finalized" {
			return fmt.Errorf("stop after capture")
		}
		return nil
	}
	if _, err := Commit(context.Background(), options); err == nil || !strings.Contains(err.Error(), "commit-capture-finalized") {
		t.Fatalf("could not stop after durable capture: %v", err)
	}
}

type faultRoundTripper struct {
	base          http.RoundTripper
	match         func(*http.Request) bool
	afterResponse bool
}

func (transport *faultRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if !transport.match(request) {
		return transport.base.RoundTrip(request)
	}
	if transport.afterResponse {
		response, err := transport.base.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	return nil, fmt.Errorf("simulated lost upload response")
}

func withWriterTransport(harness *integrationHarness, wrap func(http.RoundTripper) http.RoundTripper) Options {
	options := harness.options
	options.ClientFactory = func(ctx context.Context, mirror localconfig.Mirror, role objectstore.Role) (*objectstore.Client, error) {
		access, secret := "writer", "writer-secret"
		httpClient := harness.http.Client()
		if role == objectstore.RoleReader {
			access, secret = "reader", "reader-secret"
		} else {
			clone := *httpClient
			clone.Transport = wrap(httpClient.Transport)
			httpClient = &clone
		}
		return objectstore.New(ctx, objectstore.Options{
			Mirror: mirror.Canonical, Role: role,
			CredentialsProvider: credentials.NewStaticCredentialsProvider(access, secret, ""),
			HTTPClient:          httpClient,
		})
	}
	return options
}

func TestDurableTransactionRejectsEscapingStagedPath(t *testing.T) {
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
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	ref := txn.CandidateFiles["packs.tsv"]
	ref.RelativePath = "../../outside"
	txn.CandidateFiles["packs.tsv"] = ref
	if err := run.store.Write(transactionFilename, txn); err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "staged relative path") {
		t.Fatalf("escaping durable stage path was accepted: %v", err)
	}
}

func TestDurableTransactionRejectsCatalogMismatch(t *testing.T) {
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
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
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
	entries := testIndexEntries(t, candidate)
	if len(entries) == 0 || entries[0].Kind != format.KindFile {
		t.Fatal("expected captured regular-file index entry")
	}
	entries[0].MtimeNS++
	forged, err := format.MarshalIndex(entries)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := run.ensureContentAddressedStagedBytes("candidate/forged-index-", "", forged, stagedFileRef{})
	if err != nil {
		t.Fatal(err)
	}
	txn.CandidateFiles["index.tsv"] = ref
	txn.CandidateHashes["index.tsv"] = ref.BLAKE2b
	if err := run.store.Write(transactionFilename, txn); err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "captured progress does not reproduce candidate blob") {
		t.Fatalf("captured progress/candidate mismatch was accepted: %v", err)
	}
}

func TestDurableTransactionRejectsMissingStagedCatalogPart(t *testing.T) {
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
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	_, _, packPaths, err := run.captureSegmentInputPaths(txn, true)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if len(packPaths) == 0 {
		_ = run.close()
		t.Fatal("expected captured pack progress")
	}
	if err := os.Remove(packPaths[0]); err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil {
		t.Fatal("missing captured pack progress was accepted")
	}
}

func TestDurableTransactionRejectsForgedMirrorCompletion(t *testing.T) {
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
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	progress := txn.progress("local")
	progress.RevisionComplete = true
	if err := run.store.Write(transactionFilename, txn); err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "completion") {
		t.Fatalf("forged mirror completion was accepted: %v", err)
	}
}

func TestCommitDiscardsUnrecordedMetadataStaging(t *testing.T) {
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
	metadataStage := filepath.Join(harness.options.transactionFilesPath(), "metadata")
	if err := os.Mkdir(metadataStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadataStage, "metadata.bundle.encrypted"), []byte("interrupted build"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Commit(ctx, harness.options)
	if err != nil || !isCommitID(result.CommitID) {
		t.Fatalf("commit did not discard unrecorded metadata staging: %#v %v", result, err)
	}
}

func TestResetResumesAfterControlRecordCleanupCrash(t *testing.T) {
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
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "transaction-control-cleared" {
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if err := Reset(options); err == nil || !strings.Contains(err.Error(), "transaction-control-cleared") {
		t.Fatalf("reset did not stop after clearing its control record: %v", err)
	}
	if err := Reset(harness.options); err != nil {
		t.Fatalf("reset did not clean unreferenced staging after restart: %v", err)
	}
	if _, err := os.Lstat(harness.options.transactionFilesPath()); !os.IsNotExist(err) {
		t.Fatalf("reset left unreferenced transaction files: %v", err)
	}
}

func TestCompletedTransactionResumesAfterControlRecordCleanupCrash(t *testing.T) {
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
	stopped := false
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "mirror-revision-acknowledged" && !stopped {
			stopped = true
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil {
		t.Fatal("completion checkpoint did not stop commit")
	}
	options = harness.options
	options.failurePoint = func(point string) error {
		if point == "transaction-control-cleared" {
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "transaction-control-cleared") {
		t.Fatalf("completion cleanup did not stop after its durable control boundary: %v", err)
	}
	result, err := Commit(ctx, harness.options)
	if err != nil || !isCommitID(result.CommitID) || !result.NoChanges {
		t.Fatalf("completed transaction did not recover after control cleanup: %#v %v", result, err)
	}
}

func TestCommitConfirmsLostPushThroughValidatedRemoteDescendant(t *testing.T) {
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
	stopped := false
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "git-push-returned" && !stopped {
			stopped = true
			return fmt.Errorf("simulated lost successful push response")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil {
		t.Fatal("lost-push checkpoint did not stop commit")
	}
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	blobs := testStateBlobs(t, candidate)
	blobs["ignore"] = []byte("^\\./descendant-only$\n")
	descendant, err := run.repo.CreateCommit(txn.LocalCommit, blobs, "validated descendant")
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	runGit(t, "--git-dir", harness.bare, "fetch", filepath.Join(harness.root, ".backup"), descendant+":refs/heads/main")
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	result, err := Commit(ctx, harness.options)
	if err != nil || result.CommitID != txn.LocalCommit {
		t.Fatalf("commit did not recover through remote descendant: %#v %v", result, err)
	}
}

func TestResetRefusesAnyAttemptedMetadataPush(t *testing.T) {
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
	stopped := false
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "git-push-intent-recorded" && !stopped {
			stopped = true
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil {
		t.Fatal("push-intent checkpoint did not stop commit")
	}
	if err := Reset(harness.options); err == nil || !strings.Contains(err.Error(), "push was attempted") {
		t.Fatalf("reset accepted an ambiguous attempted push: %v", err)
	}
	if _, err := Commit(ctx, harness.options); err != nil {
		t.Fatalf("commit did not remain resumable after reset refusal: %v", err)
	}
}

func TestResetAllowsAbandonAfterCompetingRemoteAdvance(t *testing.T) {
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
	stopped := false
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "git-push-intent-recorded" && !stopped {
			stopped = true
			return fmt.Errorf("simulated process stop")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil {
		t.Fatal("push-intent checkpoint did not stop commit")
	}
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	baseHistory, err := (repository.Validator{Repo: run.repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(txn.BaseCommit)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	blobs := testStateBlobs(t, testHistoryTip(t, baseHistory).State)
	blobs["ignore"] = []byte("^\\./competing-writer$\n")
	competing, err := run.repo.CreateCommit(txn.BaseCommit, blobs, "competing writer")
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	runGit(t, "--git-dir", harness.bare, "fetch", filepath.Join(harness.root, ".backup"), competing+":refs/heads/main")
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if err := Reset(harness.options); err != nil {
		t.Fatalf("reset did not allow a provably rejected stale push: %v", err)
	}
	head := strings.TrimSpace(runGit(t, "-C", filepath.Join(harness.root, ".backup"), "rev-parse", "HEAD"))
	if head != txn.BaseCommit {
		t.Fatalf("reset head=%s, want base %s", head, txn.BaseCommit)
	}
}

func TestOperationalStateDirectorySymlinkIsRejected(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	state := harness.options.statePath()
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, state); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil {
		t.Fatal("operational state symlink was accepted")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("operational state symlink target mode changed to %04o", info.Mode().Perm())
	}
}

func TestOperationalLockRejectsUnexpectedType(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(harness.options.statePath(), "lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(lock, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("FIFO operational lock was accepted: %v", err)
	}
}

func TestDurableTransactionRejectsChangedStagedBytes(t *testing.T) {
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
	options := harness.options
	options.failurePoint = func(point string) error {
		if point == "metadata-staged" {
			return fmt.Errorf("stop after metadata staging")
		}
		return nil
	}
	if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "metadata-staged") {
		t.Fatalf("could not stop after metadata staging: %v", err)
	}
	run, err := openRuntime(harness.options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if txn.Metadata == nil || len(txn.Metadata.Manifest.Parts) == 0 {
		_ = run.close()
		t.Fatal("expected staged metadata part")
	}
	relative, err := metadataPartRelative(txn.Metadata, 0)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	path, err := run.stagedPath(relative)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, harness.options); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("changed staged bytes were accepted: %v", err)
	}
}

func TestResetResumesAfterRemovingTransactionState(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
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
	commit, err := run.repo.CreateCommitState(txn.BaseCommit, candidate, "test reset candidate")
	if err != nil {
		t.Fatal(err)
	}
	txn.LocalCommit = commit
	if err := run.repo.MaterializeState(candidate); err != nil {
		t.Fatal(err)
	}
	if err := run.repo.AcceptCommit(commit, txn.BaseCommit); err != nil {
		t.Fatal(err)
	}
	txn.LocalAccepted = true
	if err := run.saveTransaction(txn); err != nil {
		t.Fatal(err)
	}
	history, err := (repository.Validator{Repo: run.repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.repo.MaterializeState(testHistoryTip(t, history).State); err != nil {
		t.Fatal(err)
	}
	if err := run.repo.AcceptCommit(genesis.CommitID, commit); err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}

	if err := Reset(harness.options); err != nil {
		t.Fatalf("resume reset after branch rollback: %v", err)
	}
	head := strings.TrimSpace(runGit(t, "-C", filepath.Join(harness.root, ".backup"), "rev-parse", "HEAD"))
	if head != genesis.CommitID {
		t.Fatalf("head=%s genesis=%s", head, genesis.CommitID)
	}
}

func TestResetRepairsWorktreeAfterCrashFollowingBranchRollback(t *testing.T) {
	harness := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := Init(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(harness.root, "file"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, harness.options, false); err != nil {
		t.Fatal(err)
	}
	captureTestTransaction(t, harness)
	run, err := openRuntime(harness.options, true)
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
	commit, err := run.repo.CreateCommitState(txn.BaseCommit, candidate, "test reset candidate")
	if err != nil {
		t.Fatal(err)
	}
	txn.LocalCommit = commit
	if err := run.repo.MaterializeState(candidate); err != nil {
		t.Fatal(err)
	}
	if err := run.repo.AcceptCommit(commit, txn.BaseCommit); err != nil {
		t.Fatal(err)
	}
	if err := run.repo.AcceptCommit(genesis.CommitID, commit); err != nil {
		t.Fatal(err)
	}
	// Model a crash after the branch rollback and its durable state update but
	// before the parent metadata was rematerialized.
	txn.LocalAccepted = false
	txn.Resetting = true
	if err := run.saveTransaction(txn); err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}

	if err := Reset(harness.options); err != nil {
		t.Fatalf("resume reset after branch rollback: %v", err)
	}
	repo, err := repository.OpenManaged(filepath.Join(harness.root, ".backup"), harness.bare, "main")
	if err != nil {
		t.Fatal(err)
	}
	status, err := repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Clean {
		t.Fatalf("reset left a mixed candidate worktree: %#v", status.Paths)
	}
}

func firstTestPackPart(t *testing.T, state repository.State) format.PackEntry {
	t.Helper()
	var part format.PackEntry
	if err := state.WalkPacks(format.DefaultLimits(), func(entry format.PackEntry) error {
		if part.PackHash == "" {
			part = entry
		}
		return nil
	}); err != nil || part.PackHash == "" {
		t.Fatalf("read first pack part: %#v %v", part, err)
	}
	return part
}

func testHistoryTip(t *testing.T, history *repository.History) repository.ValidatedCommit {
	t.Helper()
	if history == nil {
		t.Fatal("nil validated history")
	}
	t.Cleanup(func() { _ = history.Close() })
	tip, err := history.Tip()
	if err != nil {
		t.Fatal(err)
	}
	return tip
}

func testHistoryGenesisFormat(t *testing.T, history *repository.History) format.RepositoryFormat {
	t.Helper()
	if history == nil {
		t.Fatal("nil validated history")
	}
	t.Cleanup(func() { _ = history.Close() })
	value, err := history.GenesisFormat()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testIndexEntries(t *testing.T, state repository.State) []format.IndexEntry {
	t.Helper()
	var entries []format.IndexEntry
	if err := state.WalkIndex(format.DefaultLimits(), func(entry format.IndexEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func testObjectEntries(t *testing.T, state repository.State) []format.ObjectEntry {
	t.Helper()
	var entries []format.ObjectEntry
	if err := state.WalkObjects(format.DefaultLimits(), func(entry format.ObjectEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func testPackEntries(t *testing.T, state repository.State) []format.PackEntry {
	t.Helper()
	var entries []format.PackEntry
	if err := state.WalkPacks(format.DefaultLimits(), func(entry format.PackEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func testStateBlobs(t *testing.T, state repository.State) map[string][]byte {
	t.Helper()
	blobs := make(map[string][]byte, len(repository.RequiredBlobNames))
	for _, name := range repository.RequiredBlobNames {
		size := state.BlobSizes[name]
		if size > uint64(^uint64(0)>>1) {
			t.Fatalf("test metadata blob %s is not representable", name)
		}
		data, err := state.ReadBlob(name, int64(size))
		if err != nil {
			t.Fatalf("read test metadata blob %s: %v", name, err)
		}
		blobs[name] = data
	}
	return blobs
}

func testMirrorClient(t *testing.T, ctx context.Context, harness *integrationHarness, role objectstore.Role) *objectstore.Client {
	t.Helper()
	config, err := localconfig.Load(harness.configPath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := harness.options.ClientFactory(ctx, config.Mirrors[0], role)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func cloneTestManifest(manifest format.MetadataManifest) format.MetadataManifest {
	manifest.Parts = append([]format.ManifestPart(nil), manifest.Parts...)
	return manifest
}

func uploadTestManifest(t *testing.T, ctx context.Context, writer *objectstore.Client, manifest format.MetadataManifest, objectID string) manifestRepresentation {
	t.Helper()
	data, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	identity := objectstore.HashBytes(data)
	key, err := format.MetadataManifestKey(manifest.TipCommit, identity.BLAKE2b, objectID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := writer.PutFile(ctx, key, path, identity)
	if result.Disposition != objectstore.CreateAcknowledged {
		t.Fatalf("upload manifest %s: disposition=%d err=%v", key, result.Disposition, result.Err)
	}
	return manifestRepresentation{Key: key, Hash: identity.BLAKE2b, ObjectID: objectID, Manifest: manifest, Data: data}
}

func uploadTestMetadataBundle(t *testing.T, ctx context.Context, writer *objectstore.Client, repo *repository.Managed, repositoryUUID, base, tip string, sequence uint64, publicKey []byte, partSize uint64) manifestRepresentation {
	t.Helper()
	stage := t.TempDir()
	built, err := metadatachain.Build(repo, repositoryUUID, base, tip, sequence, [][]byte{publicKey}, stage, partSize, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range built.Parts {
		key, keyErr := format.MetadataPartKey(part.Manifest)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		expected := objectstore.Object{Size: part.Manifest.Size, BLAKE2b: part.Manifest.Hash, SHA256: part.Manifest.SHA256, MD5: part.Manifest.MD5}
		result := writer.PutFile(ctx, key, part.Path, expected)
		if result.Disposition != objectstore.CreateAcknowledged {
			t.Fatalf("upload metadata part %s: disposition=%d err=%v", key, result.Disposition, result.Err)
		}
	}
	data, err := os.ReadFile(built.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := format.MetadataManifestKey(tip, built.ManifestHash, built.ManifestObjectID)
	if err != nil {
		t.Fatal(err)
	}
	result := writer.PutFile(ctx, key, built.ManifestPath, objectstore.HashBytes(data))
	if result.Disposition != objectstore.CreateAcknowledged {
		t.Fatalf("upload metadata manifest %s: disposition=%d err=%v", key, result.Disposition, result.Err)
	}
	return manifestRepresentation{Key: key, Hash: built.ManifestHash, ObjectID: built.ManifestObjectID, Manifest: built.Manifest, Data: data}
}

func runGit(t *testing.T, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}

type testIndexedHistory []string

func (history testIndexedHistory) IndexOf(commitID string) (int, bool, error) {
	for index, candidate := range history {
		if candidate == commitID {
			return index, true, nil
		}
	}
	return -1, false, nil
}

func TestSyncDoesNotRegressCompletionLedger(t *testing.T) {
	ledger := newCompletionLedger("123e4567-e89b-42d3-a456-426614174000")
	newer := strings.Repeat("b", 64)
	older := strings.Repeat("a", 64)
	ledger.Mirrors["destination"] = newer
	if err := updateCompletionLedgerForSync(&ledger, "destination", older, testIndexedHistory{older, newer}); err == nil {
		t.Fatal("sync regressed a destination completion ledger from a newer descendant")
	}
	if ledger.Mirrors["destination"] != newer {
		t.Fatalf("ledger changed to %s", ledger.Mirrors["destination"])
	}
}

func TestApplyMetadataBundleRejectsUnexpectedAdvertisedRef(t *testing.T) {
	harness := newIntegrationHarness(t)
	genesis, err := Init(context.Background(), harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	repoPath := filepath.Join(harness.root, ".backup")
	tipRef := "refs/backup/bundle-tip"
	otherRef := "refs/backup/unexpected"
	runGit(t, "-C", repoPath, "update-ref", tipRef, genesis.CommitID)
	runGit(t, "-C", repoPath, "update-ref", otherRef, genesis.CommitID)
	defer runGit(t, "-C", repoPath, "update-ref", "-d", tipRef)
	defer runGit(t, "-C", repoPath, "update-ref", "-d", otherRef)
	bundle := filepath.Join(t.TempDir(), "unexpected-ref.bundle")
	runGit(t, "-C", repoPath, "bundle", "create", bundle, tipRef, otherRef)
	quarantine, err := initializeMetadataQuarantine(filepath.Join(t.TempDir(), "quarantine.git"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := format.MetadataManifest{Kind: format.BundleFull, BaseCommit: "-", TipCommit: genesis.CommitID}
	if err := applyMetadataBundle(quarantine, bundle, manifest, strings.Repeat("0", 64)); err == nil {
		t.Fatal("bundle advertising an unexpected ref was accepted")
	}
}
