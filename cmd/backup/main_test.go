package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/s3server"
	"github.com/nathants/go-libsodium"
)

func TestCLIHelpAndUnknownCommand(t *testing.T) {
	backupBin := buildBackupBinary(t)

	type testCase struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}

	tests := []testCase{
		{
			name:       "no args prints usage",
			args:       []string{},
			wantCode:   1,
			wantStdout: "Usage:",
		},
		{
			name:       "help prints usage",
			args:       []string{"--help"},
			wantCode:   1,
			wantStdout: "Usage:",
		},
		{
			name:       "unknown command prints usage and error",
			args:       []string{"nope"},
			wantCode:   1,
			wantStdout: "Usage:",
			wantStderr: "unknown command:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runCLI(t, backupBin, test.args, nil)
			if result.ExitCode != test.wantCode {
				t.Fatalf("unexpected exit code: got=%d want=%d\nstdout=%s\nstderr=%s", result.ExitCode, test.wantCode, result.Stdout, result.Stderr)
			}
			if test.wantStdout != "" && !strings.Contains(result.Stdout, test.wantStdout) {
				t.Fatalf("unexpected stdout:\nwant contains=%q\nstdout=%s", test.wantStdout, result.Stdout)
			}
			if test.wantStderr != "" && !strings.Contains(result.Stderr, test.wantStderr) {
				t.Fatalf("unexpected stderr:\nwant contains=%q\nstderr=%s", test.wantStderr, result.Stderr)
			}
		})
	}
}

func TestUsageListsCommands(t *testing.T) {
	output := captureStdout(t, func() {
		usage()
	})
	if !strings.Contains(output, "Usage:") {
		t.Fatalf("expected Usage header, got:\n%s", output)
	}
	// Spot-check some expected commands are present.
	for _, name := range []string{"init", "add", "commit", "restore", "server"} {
		if !strings.Contains(output, "backup "+name) {
			t.Fatalf("expected usage output to mention %q, got:\n%s", "backup "+name, output)
		}
	}
}

func TestCLIEndToEnd(t *testing.T) {
	backupBin := buildBackupBinary(t)

	root := t.TempDir()
	remote := filepath.Join(t.TempDir(), "remote.git")
	runCommand(t, "git", "init", "--bare", remote)

	serverDir := filepath.Join(t.TempDir(), "objects")
	server := &s3server.Server{Dir: serverDir, AccessKey: "test", SecretKey: "secret", Region: "us-east-1"}
	tlsServer := httptest.NewTLSServer(server)
	defer tlsServer.Close()

	publicKey, secretKey := makeKeys(t)

	env := map[string]string{
		"BACKUP_ROOT":              root,
		"BACKUP_GIT":               remote,
		"BACKUP_S3":                "s3://bucket/test",
		"BACKUP_S3_ENDPOINT":       tlsServer.URL,
		"BACKUP_S3_REGION":         "us-east-1",
		"BACKUP_S3_INSECURE_TLS":   "1",
		"BACKUP_CHUNK_MEGABYTES":   "1",
		"AWS_ACCESS_KEY_ID":        "test",
		"AWS_SECRET_ACCESS_KEY":    "secret",
		"GIT_REMOTE_AWS_PUBLICKEY": hex.EncodeToString(publicKey),
		"GIT_REMOTE_AWS_SECRETKEY": hex.EncodeToString(secretKey),
	}

	runCLIExpectOK(t, backupBin, []string{"init"}, env)

	err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha"), 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	runCLIExpectOK(t, backupBin, []string{"add"}, env)
	diff := runCLIExpectOK(t, backupBin, []string{"diff"}, env)
	if !strings.Contains(diff.Stdout, "addition:") {
		t.Fatalf("expected diff to contain addition, got:\n%s", diff.Stdout)
	}

	runCLIExpectOK(t, backupBin, []string{"commit"}, env)

	secondRoot := t.TempDir()
	env["BACKUP_ROOT"] = secondRoot
	runCLIExpectOK(t, backupBin, []string{"restore", "alpha", "HEAD"}, env)
	assertFile(t, filepath.Join(secondRoot, "alpha.txt"), "alpha")
}

type cliResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

func runCLIExpectOK(t *testing.T, backupBin string, args []string, env map[string]string) cliResult {
	t.Helper()
	result := runCLI(t, backupBin, args, env)
	if result.ExitCode != 0 {
		t.Fatalf("command failed: backup %s\nexitCode=%d\nstdout=%s\nstderr=%s", strings.Join(args, " "), result.ExitCode, result.Stdout, result.Stderr)
	}
	return result
}

func runCLI(t *testing.T, backupBin string, args []string, env map[string]string) cliResult {
	t.Helper()
	cmd := exec.Command(backupBin, args...)
	cmd.Env = mergeEnv(os.Environ(), env)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run: %v", err)
		}
		exitCode = exitErr.ExitCode()
	}
	return cliResult{ExitCode: exitCode, Stdout: stdout.String(), Stderr: stderr.String()}
}

func mergeEnv(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	result := make([]string, 0, len(base)+len(overrides))
	seen := map[string]bool{}
	for key := range overrides {
		seen[key] = true
	}
	for _, value := range base {
		key, _, ok := strings.Cut(value, "=")
		if ok && seen[key] {
			continue
		}
		result = append(result, value)
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func buildBackupBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "backup")
	cmd := exec.Command("go", "build", "-o", out, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("go build failed: %v: %s", err, stderr.String())
	}
	return out
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = original
	})
	fn()
	_ = writer.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}
