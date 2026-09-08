package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestPermissionSkipsPreserveAddSelectionAtCommit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	h := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"denied-at-add", "denied-at-commit", "keep"} {
		path := filepath.Join(h.root, name)
		if err := os.WriteFile(path, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	}
	deniedAtAdd := filepath.Join(h.root, "denied-at-add")
	deniedAtCommit := filepath.Join(h.root, "denied-at-commit")
	if err := os.Chmod(deniedAtAdd, 0000); err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	options := h.options
	options.Stderr = &diagnostics
	added, err := Add(ctx, options, false)
	if err != nil || added.Scan.SkippedPermissionDenied != 1 {
		t.Fatalf("add permission skip: %+v, %v", added, err)
	}
	if !strings.Contains(diagnostics.String(), "permission-denied-skipped\t./denied-at-add\t") {
		t.Fatalf("add omitted its permission warning: %q", diagnostics.String())
	}
	if err := os.Chmod(deniedAtAdd, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(deniedAtCommit, 0000); err != nil {
		t.Fatal(err)
	}
	diagnostics.Reset()
	if _, err := Commit(ctx, options); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diagnostics.String(), "warning: ./denied-at-commit:") || !strings.Contains(diagnostics.String(), "permission denied") || !strings.Contains(diagnostics.String(), "; omitted") {
		t.Fatalf("commit omitted its permission warning: %q", diagnostics.String())
	}
	seen := map[string]bool{}
	if _, err := Find(options, ".*", "HEAD", nil, func(row format.IndexEntry) error { seen[row.Path] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !seen["./keep"] || seen["./denied-at-add"] || seen["./denied-at-commit"] {
		t.Fatalf("commit changed add selection or included unreadable content: %v", seen)
	}

	if err := os.WriteFile(filepath.Join(h.root, ".backup", "ignore"), []byte("^\\./\\.backup-config$\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, options, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"denied-at-add", "keep"} {
		if err := os.Chmod(filepath.Join(h.root, name), 0000); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "every path selected by add") {
		t.Fatalf("all-denied capture bypassed the empty-snapshot guard: %v", err)
	}
}
