package objectstore

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

func TestTrustedCARejectsFIFOWithoutBlocking(t *testing.T) {
	if path := os.Getenv("BACKUP_CA_FIFO_TEST"); path != "" {
		if _, err := readTrustedCAFile(path); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO did not fail regular-file validation: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// No writer is connected; cleanup must not depend on the reader returning.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTrustedCARejectsFIFOWithoutBlocking$")
	child.Env = append(os.Environ(), "BACKUP_CA_FIFO_TEST="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("FIFO reader failed or blocked: %v (context: %v)\n%s", err, ctx.Err(), output)
	}
}
