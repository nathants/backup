package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nathants/go-libsodium"
)

func TestFilesystemCLIWithoutMountedDisk(t *testing.T) {
	ctx := context.Background()
	invoke := func(args ...string) string {
		t.Helper()
		var output, diagnostics bytes.Buffer
		if err := run(ctx, args, &output, &diagnostics); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, diagnostics.String())
		}
		return output.String()
	}
	for _, args := range [][]string{{"mirror-init", "--help"}, {"verify", "--help"}} {
		help := invoke(args...)
		if !strings.Contains(help, "filesystem") {
			t.Fatalf("missing help: %s", help)
		}
	}
	directory := t.TempDir()
	initialized := invoke("mirror-init", "--directory", directory)
	identity := strings.TrimSuffix(strings.TrimPrefix(initialized, "store\t"), "\n")
	if !strings.HasPrefix(identity, "filesystem://") {
		t.Fatalf("initialization output: %s", initialized)
	}
	root := t.TempDir()
	primary := filepath.Join(t.TempDir(), "primary.git")
	command := exec.Command("git", "init", "--bare", "--object-format=sha256", "--initial-branch=main", primary)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %s %v", out, err)
	}
	config := filepath.Join(t.TempDir(), "config")
	data := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tdisk\tfilesystem\t%s\t-\t-\t%s\t-\n", primary, identity, directory)
	if err := os.WriteFile(config, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BACKUP_ROOT", root)
	t.Setenv("BACKUP_CONFIG", config)
	t.Setenv("AWS_ENDPOINT_URL", "http://must-not-be-used.example")
	invoke("init")
	libsodium.Init()
	public, secret, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".backup", ".publickeys"), []byte(fmt.Sprintf("%x\n", public)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invoke("add")
	invoke("diff")
	committed := invoke("commit")
	if !strings.Contains(committed, "disk") {
		t.Fatalf("no completion: %s", committed)
	}
	invoke("verify")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", secret))
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_FILE", "")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_CMD", "")
	invoke("verify", "--full")
	target := t.TempDir()
	invoke("restore", "--target", target, ".*")
	if restored, err := os.ReadFile(filepath.Join(target, "hello")); err != nil || string(restored) != "hello\n" {
		t.Fatalf("restore: %q %v", restored, err)
	}
}
