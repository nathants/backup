package commands

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

func TestCommandWrappersEndToEnd(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

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

	os.Args = []string{"backup"}
	runInit()

	err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	os.Args = []string{"backup"}
	runAdd()
	runDiff()
	runCommit()

	os.Args = []string{"backup", "alpha", "HEAD"}
	runFind()

	secondRoot := t.TempDir()
	setEnv(t, "BACKUP_ROOT", secondRoot)
	os.Args = []string{"backup", "alpha", "HEAD"}
	runRestore()

	assertFile(t, filepath.Join(secondRoot, "alpha.txt"), "alpha")
}

func makeKeys(t *testing.T) ([]byte, []byte) {
	t.Helper()
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return publicKey, secretKey
}

func assertFile(t *testing.T, path string, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != expected {
		t.Fatalf("expected %s to be %s", path, expected)
	}
}

func runCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", strings.Join(append([]string{name}, args...), " "), err, stderr.String())
	}
}

func setEnv(t *testing.T, key string, value string) {
	t.Helper()
	original, had := os.LookupEnv(key)
	err := os.Setenv(key, value)
	if err != nil {
		t.Fatalf("setenv %s: %v", key, err)
	}
	t.Cleanup(func() {
		if !had {
			_ = os.Unsetenv(key)
			return
		}
		_ = os.Setenv(key, original)
	})
}
