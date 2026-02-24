package backup

import (
	"bytes"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/s3server"
	"github.com/nathants/go-libsodium"
)

func TestBasicBackupFlow(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "BACKUP_CHUNK_MEGABYTES", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add: %v", err)
	}
	diffs, err := Diff(config)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(diffs) != 1 || diffs[0].Kind != DiffAddition {
		t.Fatalf("expected one addition")
	}
	if err := Commit(config); err != nil {
		t.Fatalf("commit: %v", err)
	}

	entries, err := Find(config, "alpha", "HEAD")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one entry")
	}

	secondRoot := t.TempDir()
	setEnv(t, "BACKUP_ROOT", secondRoot)
	configRestore, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("restore config: %v", err)
	}
	_, err = Restore(configRestore, "alpha", "HEAD", false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	assertFile(t, filepath.Join(secondRoot, "alpha.txt"), "alpha")
}

func TestSymlinkRestore(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := Commit(config); err != nil {
		t.Fatalf("commit: %v", err)
	}

	secondRoot := t.TempDir()
	setEnv(t, "BACKUP_ROOT", secondRoot)
	configRestore, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("restore config: %v", err)
	}
	_, err = Restore(configRestore, "link.txt", "HEAD", false)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	linkTarget, err := os.Readlink(filepath.Join(secondRoot, "link.txt"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if linkTarget != "target.txt" {
		t.Fatalf("expected relative symlink, got %s", linkTarget)
	}
	assertFile(t, filepath.Join(secondRoot, "target.txt"), "data")
}

func TestChunking(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "BACKUP_CHUNK_MEGABYTES", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}
	payloadA := bytes.Repeat([]byte("a"), 1024*1024)
	if err := os.WriteFile(filepath.Join(root, "chunk1.bin"), payloadA, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	payloadB := bytes.Repeat([]byte("b"), 1024*1024)
	if err := os.WriteFile(filepath.Join(root, "chunk2.bin"), payloadB, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := Commit(config); err != nil {
		t.Fatalf("commit: %v", err)
	}
	packs, err := ReadPacks(filepath.Join(root, ".backup", "packs.tsv"))
	if err != nil {
		t.Fatalf("packs: %v", err)
	}
	if len(packs) < 2 {
		t.Fatalf("expected multiple packs")
	}
}

func TestReset(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "temp.txt"), []byte("temp"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := Reset(config); err != nil {
		t.Fatalf("reset: %v", err)
	}
	entries, err := ReadIndex(filepath.Join(root, ".backup", "index.tsv"))
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty index after reset")
	}
}

func TestImmutability(t *testing.T) {
	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	setEnv(t, "BACKUP_ROOT", t.TempDir())
	setEnv(t, "BACKUP_GIT", filepath.Join(t.TempDir(), "remote.git"))
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	client, err := NewS3Client(config)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	payload := bytes.NewReader([]byte("payload"))
	_, _, err = client.PutObject(t.Context(), config.S3Bucket, ObjectKey(config.S3Prefix, "object"), payload)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	payload = bytes.NewReader([]byte("payload"))
	_, _, err = client.PutObject(t.Context(), config.S3Bucket, ObjectKey(config.S3Prefix, "object"), payload)
	if err == nil {
		t.Fatalf("expected immutability error")
	}
}

func TestSymlinkOutsideRootIsSkipped(t *testing.T) {
	root := t.TempDir()
	root2 := root + "2"
	if err := os.MkdirAll(root2, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(root2, "outside.txt")
	if err := os.WriteFile(target, []byte("outside"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	result, err := ScanRoot(root, Ignore{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, entry := range result.Entries {
		if entry.Kind == "symlink" {
			t.Fatalf("expected symlink to be skipped, got %v", entry)
		}
	}
}

func TestRestoreRejectsMaliciousIndexPaths(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}

	backupDir := config.BackupDir()
	// Write a malicious index that would traverse outside the root if not rejected.
	malicious := "./../pwn.txt\tfile\tblake2b:" + strings.Repeat("0", 128) + "\t1\t644\n"
	if err := os.WriteFile(filepath.Join(backupDir, "index.tsv"), []byte(malicious), 0644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := gitAdd(backupDir, "index.tsv"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if err := gitCommit(backupDir, []string{"malicious index"}); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	if err := gitPush(backupDir); err != nil {
		t.Fatalf("git push: %v", err)
	}

	secondRoot := t.TempDir()
	setEnv(t, "BACKUP_ROOT", secondRoot)
	configRestore, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("restore config: %v", err)
	}
	_, err = Restore(configRestore, "pwn", "HEAD", false)
	if err == nil {
		t.Fatalf("expected restore to fail for malicious index")
	}
	// Ensure we didn't create a file outside the root.
	if _, statErr := os.Stat(filepath.Join(secondRoot, "..", "pwn.txt")); statErr == nil {
		t.Fatalf("restore wrote outside root")
	}
}

func TestRestoreErrorsIfPackMissingRequiredHash(t *testing.T) {
	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)
	setEnv(t, "BACKUP_ROOT", root)
	setEnv(t, "BACKUP_GIT", remote)
	setEnv(t, "BACKUP_S3", "s3://bucket/test")
	setEnv(t, "BACKUP_S3_ENDPOINT", tlsServer.URL)
	setEnv(t, "BACKUP_S3_REGION", "us-east-1")
	setEnv(t, "BACKUP_S3_INSECURE_TLS", "1")
	setEnv(t, "BACKUP_CHUNK_MEGABYTES", "1")
	setEnv(t, "AWS_ACCESS_KEY_ID", "test")
	setEnv(t, "AWS_SECRET_ACCESS_KEY", "secret")
	setEnv(t, "GIT_REMOTE_AWS_PUBLICKEY", hex.EncodeToString(publicKey))
	setEnv(t, "GIT_REMOTE_AWS_SECRETKEY", hex.EncodeToString(secretKey))

	config, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := InitRepo(config); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Commit alpha.
	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0644); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := Commit(config); err != nil {
		t.Fatalf("commit alpha: %v", err)
	}
	alphaHash, _, err := hashFile(filepath.Join(root, "alpha.txt"))
	if err != nil {
		t.Fatalf("hash alpha: %v", err)
	}

	// Commit beta so we have a valid pack that doesn't contain alpha's hash.
	if err := os.WriteFile(filepath.Join(root, "beta.txt"), []byte("beta"), 0644); err != nil {
		t.Fatalf("write beta: %v", err)
	}
	if err := Add(config); err != nil {
		t.Fatalf("add beta: %v", err)
	}
	if err := Commit(config); err != nil {
		t.Fatalf("commit beta: %v", err)
	}

	backupDir := config.BackupDir()
	objects, err := ReadObjects(filepath.Join(backupDir, "objects.tsv"))
	if err != nil {
		t.Fatalf("read objects: %v", err)
	}
	betaHash, _, err := hashFile(filepath.Join(root, "beta.txt"))
	if err != nil {
		t.Fatalf("hash beta: %v", err)
	}
	var betaPackKey string
	for _, entry := range objects {
		if entry.Hash == betaHash {
			betaPackKey = entry.PackKey
			break
		}
	}
	if betaPackKey == "" {
		t.Fatalf("missing beta pack key")
	}
	for i := range objects {
		if objects[i].Hash == alphaHash {
			objects[i].PackKey = betaPackKey
		}
	}
	SortObjects(objects)
	if err := WriteObjects(filepath.Join(backupDir, "objects.tsv"), objects); err != nil {
		t.Fatalf("write objects: %v", err)
	}
	if err := gitAdd(backupDir, "objects.tsv"); err != nil {
		t.Fatalf("git add: %v", err)
	}
	if err := gitCommit(backupDir, []string{"corrupt objects mapping"}); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	if err := gitPush(backupDir); err != nil {
		t.Fatalf("git push: %v", err)
	}

	secondRoot := t.TempDir()
	setEnv(t, "BACKUP_ROOT", secondRoot)
	configRestore, err := LoadConfig(Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		t.Fatalf("restore config: %v", err)
	}
	_, err = Restore(configRestore, "alpha", "HEAD", false)
	if err == nil {
		t.Fatalf("expected restore to fail due to missing hash in pack")
	}
}

func makeKeys(t *testing.T) ([]byte, []byte) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return publicKey, secretKey
}

func assertFile(t *testing.T, path string, expected string) {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != expected {
		t.Fatalf("expected %s to be %s", path, expected)
	}
}

func runCommand(t *testing.T, name string, args ...string) {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v: %s", strings.Join(append([]string{name}, args...), " "), err, stderr.String())
	}
}

func setEnv(t *testing.T, key string, value string) {
	err := os.Setenv(key, value)
	if err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
}
