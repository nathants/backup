package backup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
)

func TestReplanReusesObservationsAndDiscoversCurrentSelection(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint("published=", published), func(t *testing.T) {
			h := newIntegrationHarness(t)
			ctx := context.Background()
			if published {
				if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
					t.Fatal(err)
				}
			} else if _, err := initWithKeys(ctx, h.options, h.publicKey); err != nil {
				t.Fatal(err)
			}
			write := func(name, text string) {
				t.Helper()
				mode := os.FileMode(0600)
				if name == ".backup/ignore" {
					mode = 0644
				}
				if err := os.WriteFile(filepath.Join(h.root, name), []byte(text), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("known", "original")
			write("hidden", "newly admitted")
			write("gone", "disappears")
			write(".backup/ignore", "^\\./(hidden|\\.backup-config)$\n")
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			write("known", "changed after add")
			write("late", "created after add")
			if err := os.Remove(filepath.Join(h.root, "gone")); err != nil {
				t.Fatal(err)
			}
			write(".backup/ignore", "^\\./(known|\\.backup-config)$\n")
			if err := os.Rename(h.bare, h.bare+".offline"); err != nil {
				t.Fatal(err)
			}
			first, err := Replan(ctx, h.options)
			if err != nil {
				t.Fatal(err)
			}
			if first.Entries != 2 || first.Scan.HashedFiles != 2 || first.Scan.ReusedFiles != 0 {
				t.Fatalf("first replan: %+v", first)
			}
			write(".backup/ignore", "^\\./\\.backup-config$\n")
			second, err := Replan(ctx, h.options)
			if err != nil {
				t.Fatal(err)
			}
			if second.Entries != 3 || second.Scan.HashedFiles != 0 || second.Scan.ReusedFiles != 3 {
				t.Fatalf("second replan: %+v", second)
			}
			var known format.IndexEntry
			if _, err := DiffCandidate(h.options, func(d Diff) error {
				if d.New != nil && d.New.Path == "./known" {
					known = *d.New
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			digest := blake2b.Sum512([]byte("original"))
			if known.Ref != fmt.Sprintf("blake2b:%x", digest) {
				t.Fatalf("replan refreshed retained content: %+v", known)
			}
			if err := os.Rename(h.bare+".offline", h.bare); err != nil {
				t.Fatal(err)
			}
			write("after-replan", "must not commit")
			interrupted := h.options
			interrupted.failurePoint = func(point string) error {
				if point == "commit-capture-started" {
					return fmt.Errorf("injected capture stop")
				}
				return nil
			}
			if _, err := Commit(ctx, interrupted); err == nil || !strings.Contains(err.Error(), "injected capture stop") {
				t.Fatalf("capture injection: %v", err)
			}
			if _, err := Replan(ctx, h.options); err == nil || !strings.Contains(err.Error(), "progress") {
				t.Fatalf("replan changed capture progress: %v", err)
			}
			if _, err := Commit(ctx, h.options); err != nil {
				t.Fatal(err)
			}
			var committed []format.IndexEntry
			if _, err := Find(h.options, ".*", "HEAD", nil, func(e format.IndexEntry) error { committed = append(committed, e); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(committed) != 3 {
				t.Fatalf("committed unexpected selection: %+v", committed)
			}
			want := map[string]string{"./known": "changed after add", "./hidden": "newly admitted", "./late": "created after add"}
			for _, e := range committed {
				content, ok := want[e.Path]
				digest := blake2b.Sum512([]byte(content))
				if !ok || e.Ref != fmt.Sprintf("blake2b:%x", digest) || e.Size != uint64(len(content)) {
					t.Fatalf("commit did not capture the replanned selection: %+v", e)
				}
			}
			t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
			target := t.TempDir()
			if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: ".*", Revision: "HEAD", TargetRoot: target}); err != nil {
				t.Fatal(err)
			}
			for path, content := range want {
				data, err := os.ReadFile(filepath.Join(target, path))
				if err != nil || string(data) != content {
					t.Fatalf("restored %s: %q %v", path, data, err)
				}
			}
		})
	}
}

func newReplanPreparation(t *testing.T) (Options, func(string, string)) {
	t.Helper()
	options := Options{Root: t.TempDir()}
	if _, err := Init(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		t.Helper()
		mode := os.FileMode(0600)
		if strings.HasPrefix(name, ".backup/") {
			mode = 0644
		}
		if err := os.WriteFile(filepath.Join(options.Root, name), []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("keep", "old")
	write("other", "other")
	if _, err := Add(context.Background(), options, false); err != nil {
		t.Fatal(err)
	}
	return options, write
}

func TestReplanFailuresPreservePreviousPlan(t *testing.T) {
	for _, scenario := range []string{"invalid-ignore", "empty", "keys", "unrelated", "canceled", "before-publication"} {
		t.Run(scenario, func(t *testing.T) {
			options, write := newReplanPreparation(t)
			path := filepath.Join(options.Root, ".backup", operationalStateDirName, transactionFilename)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch scenario {
			case "invalid-ignore":
				write(".backup/ignore", "[\n")
			case "empty":
				write(".backup/ignore", ".*\n")
			case "keys":
				write(".backup/.publickeys", "\n")
			case "unrelated":
				write(".backup/untracked", "bad")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "before-publication":
				write(".backup/ignore", "other\n")
				options.failurePoint = func(point string) error {
					if point == "replan-built" {
						return fmt.Errorf("injected")
					}
					return nil
				}
			}
			if _, err := Replan(ctx, options); err == nil {
				t.Fatal("invalid replan succeeded")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed replan changed durable plan: %v", err)
			}
			options.failurePoint = nil
			write(".backup/ignore", "")
			write(".backup/.publickeys", "")
			if scenario == "unrelated" {
				if err := os.Remove(filepath.Join(options.Root, ".backup/untracked")); err != nil {
					t.Fatal(err)
				}
			}
			result, err := Replan(context.Background(), options)
			if err != nil || result.Entries != 2 || result.Scan.ReusedFiles != 2 {
				t.Fatalf("old plan unusable after failure: %+v %v", result, err)
			}
		})
	}
}

func TestReplanPublicationCrashAndFullAddResetObservations(t *testing.T) {
	options, write := newReplanPreparation(t)
	ctx := context.Background()
	write(".backup/ignore", "other\n")
	options.failurePoint = func(point string) error {
		if point == "replan-recorded" {
			return fmt.Errorf("injected")
		}
		return nil
	}
	if _, err := Replan(ctx, options); err == nil {
		t.Fatal("failure injection missed")
	}
	options.failurePoint = nil
	var paths []string
	if _, err := DiffCandidate(options, func(d Diff) error { paths = append(paths, d.New.Path); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "./keep" {
		t.Fatalf("published replacement not durable: %v", paths)
	}
	write("other", "modified")
	write(".backup/ignore", "")
	result, err := Replan(ctx, options)
	if err != nil || result.Scan.ReusedFiles != 2 || result.Scan.HashedFiles != 0 {
		t.Fatalf("retry lost excluded observations: %+v %v", result, err)
	}
	result, err = Add(ctx, options, false)
	if err != nil || result.Scan.HashedFiles != 2 || result.Scan.ReusedFiles != 0 {
		t.Fatalf("full add reused observations: %+v %v", result, err)
	}
	run, err := openRuntime(options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	if txn.Plan.ObservationsFile != nil {
		t.Fatal("add retained old observation inventory")
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	generations, err := os.ReadDir(filepath.Join(options.Root, ".backup", operationalStateDirName, "transaction-files", "plans"))
	if err != nil || len(generations) != 1 {
		t.Fatalf("retained obsolete plans: %v %v", generations, err)
	}
}

func TestReplanAllowEmptyAndCacheCorruption(t *testing.T) {
	options, write := newReplanPreparation(t)
	ctx := context.Background()
	write(".backup/ignore", ".*\n")
	if _, err := Add(ctx, options, true); err != nil {
		t.Fatal(err)
	}
	if result, err := Replan(ctx, options); err != nil || result.Entries != 0 {
		t.Fatalf("allow-empty not preserved: %+v %v", result, err)
	}
	write(".backup/ignore", "")
	if result, err := Replan(ctx, options); err != nil || result.Scan.HashedFiles != 2 {
		t.Fatalf("expand empty plan: %+v %v", result, err)
	}
	run, err := openRuntime(options, true)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	path, err := run.stagedPath(txn.Plan.ObservationsFile.RelativePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Replan(ctx, options); err == nil || !strings.Contains(err.Error(), "observations") {
		t.Fatalf("corrupt cache accepted: %v", err)
	}
}

func TestReplanRefreshesKindsAndGitIgnoreRules(t *testing.T) {
	options, write := newReplanPreparation(t)
	ctx := context.Background()
	if err := os.Remove(filepath.Join(options.Root, "other")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("keep", filepath.Join(options.Root, "other")); err != nil {
		t.Fatal(err)
	}
	write(".gitignore", "keep\n")
	result, err := Replan(ctx, options)
	if err != nil || result.Entries != 2 {
		t.Fatalf("file to symlink/current Git ignore: %+v %v", result, err)
	}
	var link format.IndexEntry
	if _, err := DiffCandidate(options, func(d Diff) error {
		if d.New.Path == "./other" {
			link = *d.New
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if link.Kind != format.KindSymlink || link.Ref != "target:./keep" {
		t.Fatalf("reused stale kind: %+v", link)
	}
	if err := os.Remove(filepath.Join(options.Root, "other")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(options.Root, "other"), 0700); err != nil {
		t.Fatal(err)
	}
	write("other/child", "new child")
	write(".gitignore", "")
	result, err = Replan(ctx, options)
	if err != nil || result.Entries != 3 || result.Scan.HashedFiles != 1 {
		t.Fatalf("cached leaf became ancestor: %+v %v", result, err)
	}
	if _, err := Replan(ctx, options); err != nil {
		t.Fatalf("observation union rejects former leaf: %v", err)
	}
}
