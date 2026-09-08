package backup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestGitIgnoreSelectionIsFixedByAdd(t *testing.T) {
	for _, kind := range []string{"repository", "ordinary", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			h := newIntegrationHarness(t)
			ctx := context.Background()
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			repo := filepath.Join(h.root, "repo")
			if err := os.Mkdir(repo, 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "repository":
				if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
					t.Fatalf("git init: %v: %s", err, out)
				}
			case "incomplete":
				if err := os.Mkdir(filepath.Join(repo, ".git"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name, value string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(repo, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(".gitignore", "ignored\n")
			write("ignored", "not selected")
			write("untracked", "selected")
			if err := os.WriteFile(filepath.Join(h.root, ".backup", "ignore"), []byte("^\\./repo/\\.git(/|$)\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			options := h.options
			options.Stderr = &diagnostics
			if _, err := Add(ctx, options, false); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(diagnostics.String(), "git-ignored\t./repo/ignored") {
				t.Fatal("ignored selection was not reported")
			}
			write(".gitignore", "untracked\n")
			write("after-add", "not selected")
			if _, err := Commit(ctx, options); err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			if _, err := Find(options, ".*", "HEAD", nil, func(row format.IndexEntry) error { seen[row.Path] = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if !seen["./repo/untracked"] || seen["./repo/ignored"] || seen["./repo/after-add"] {
				t.Fatalf("commit changed add-time Git ignore selection: %v", seen)
			}
		})
	}
}
