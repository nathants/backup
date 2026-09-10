package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenStagedRejectsFIFOWithoutBlocking(t *testing.T) {
	if root := os.Getenv("BACKUP_STAGED_FIFO_TEST"); root != "" {
		run := runtime{options: Options{Root: root}}
		file, err := run.openStaged("part")
		if file != nil {
			_ = file.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO did not fail regular-file validation: %v", err)
		}
		return
	}
	options := Options{Root: t.TempDir()}
	if err := os.MkdirAll(options.transactionFilesPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(options.transactionFilesPath(), "part"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOpenStagedRejectsFIFOWithoutBlocking$")
	child.Env = append(os.Environ(), "BACKUP_STAGED_FIFO_TEST="+options.Root)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("FIFO reader failed or blocked: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}

func TestOpenStagedRequiresRegularNoFollowFile(t *testing.T) {
	run := runtime{options: Options{Root: t.TempDir()}}
	directory := run.options.transactionFilesPath()
	if err := os.MkdirAll(filepath.Join(directory, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "part"), []byte("staged bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("part", filepath.Join(directory, "symlink")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"directory", "symlink"} {
		file, err := run.openStaged(path)
		if file != nil {
			_ = file.Close()
		}
		if err == nil {
			t.Errorf("accepted staged %s", path)
		}
	}
	if data, err := run.readStaged("part", 64); err != nil || string(data) != "staged bytes" {
		t.Fatalf("regular staged file was not read intact: %q %v", data, err)
	}
}
