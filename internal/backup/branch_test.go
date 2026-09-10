package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/localconfig"
	"backup/internal/objectstore"
)

func TestInitialInvalidBranchDoesNotPinPreparation(t *testing.T) {
	for _, branch := range []string{"main.lock", "archive.lock/home", "main.", "archive/.hidden", "HEAD"} {
		t.Run(branch, func(t *testing.T) {
			h := newIntegrationHarness(t)
			h.options.PackTarget, h.options.PartSize, h.options.MetadataPartSize = 1<<20, 1<<20, 1<<20
			ctx := context.Background()
			original, err := os.ReadFile(h.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			paths := []string{
				filepath.Join(h.options.statePath(), preparationFilename),
				filepath.Join(h.options.statePath(), transactionFilename),
				filepath.Join(h.root, ".backup", ".git", "config"),
				filepath.Join(h.root, ".backup", ".git", "HEAD"),
			}
			before := make(map[string][]byte, len(paths))
			for _, path := range paths {
				before[path], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			invalid := bytes.ReplaceAll(original, []byte("branch\tmain\n"), []byte("branch\t"+branch+"\n"))
			if err := os.WriteFile(h.configPath, invalid, 0600); err != nil {
				t.Fatal(err)
			}
			opts := h.options
			opts.ClientFactory = func(context.Context, localconfig.Mirror) (*objectstore.Client, error) {
				t.Error("invalid branch reached object-client construction")
				return nil, fmt.Errorf("unexpected object client")
			}
			if _, err := Commit(ctx, opts); err == nil || !strings.Contains(err.Error(), "branch") {
				t.Errorf("invalid branch was not rejected by preflight: %v", err)
			}
			for _, path := range paths {
				if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, before[path]) {
					t.Errorf("invalid branch changed durable state %s: %v", path, err)
				}
			}
			if refs := runGit(t, "--git-dir", h.bare, "for-each-ref"); refs != "" {
				t.Errorf("invalid branch published remote refs: %s", refs)
			}
			if err := os.WriteFile(h.configPath, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := Reset(h.options); err != nil {
				t.Fatalf("corrected configuration could not reset its add plan: %v", err)
			}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			result, err := Commit(ctx, h.options)
			if err != nil || !isCommitID(result.CommitID) || len(result.CompleteMirrors) != 1 {
				t.Fatalf("corrected configuration could not publish: %+v %v", result, err)
			}
		})
	}
}
