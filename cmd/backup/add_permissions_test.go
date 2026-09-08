package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddPermissionWarningsAndEmptyGuard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	for _, keepReadable := range []bool{true, false} {
		t.Run(map[bool]string{true: "readable-sibling", false: "all-denied"}[keepReadable], func(t *testing.T) {
			root := t.TempDir()
			var stdout, stderr bytes.Buffer
			if err := runInit(context.Background(), []string{"--root", root}, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			denied := filepath.Join(root, "denied\x1b")
			if err := os.WriteFile(denied, []byte("unreadable"), 0000); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Chmod(denied, 0600) }()
			if keepReadable {
				if err := os.WriteFile(filepath.Join(root, "keep"), []byte("readable"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stdout.Reset()
			stderr.Reset()
			err := runAdd(context.Background(), []string{"--root", root}, &stdout, &stderr)
			if keepReadable {
				if err != nil || !strings.Contains(stdout.String(), "entries\t1\n") || !strings.Contains(stdout.String(), "skipped-permission-denied\t1\n") {
					t.Fatalf("add did not report its successful partial selection: %v, %q", err, stdout.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), "empty snapshot plan") {
				t.Fatalf("all-denied scan bypassed the empty-plan guard: %v", err)
			}
			if !strings.Contains(stderr.String(), "permission-denied-skipped\t./denied\\x1b\t") || !strings.Contains(stderr.String(), "permission denied") || strings.ContainsRune(stderr.String(), '\x1b') {
				t.Fatalf("warning lost its escaped path or reason: %q", stderr.String())
			}
		})
	}
}
