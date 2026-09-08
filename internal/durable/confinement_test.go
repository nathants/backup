package durable

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "state")
	if err := os.Symlink(outside, state); err != nil {
		t.Fatal(err)
	}
	store, err := Open(state)
	if err == nil {
		_ = store.Close()
		t.Fatal("symlink store accepted")
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("rejected store changed outside permissions to %04o", info.Mode().Perm())
	}
}

func TestWriteUsesRetainedDirectory(t *testing.T) {
	for _, replacement := range []string{"symlink", "directory"} {
		t.Run(replacement, func(t *testing.T) {
			parent := t.TempDir()
			state := filepath.Join(parent, "state")
			store, err := Open(state)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			original := fixture{Version: 1, Name: "before"}
			if err := store.Write("transaction.json", original); err != nil {
				t.Fatal(err)
			}
			retained := filepath.Join(parent, "retained")
			if err := os.Rename(state, retained); err != nil {
				t.Fatal(err)
			}
			outside := state
			if replacement == "symlink" {
				outside = filepath.Join(parent, "outside")
			}
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			if replacement == "symlink" {
				if err := os.Symlink(outside, state); err != nil {
					t.Fatal(err)
				}
			}
			outsideFile := filepath.Join(outside, "transaction.json")
			if err := os.WriteFile(outsideFile, []byte("keep outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			updated := fixture{Version: 1, Name: "after"}
			if err := store.Write("transaction.json", updated); err != nil {
				t.Fatal(err)
			}
			var got fixture
			if err := store.Read("transaction.json", &got); err != nil {
				t.Fatal(err)
			}
			if got != updated {
				t.Errorf("write did not update retained store: got=%+v want=%+v", got, updated)
			}
			if data, err := os.ReadFile(outsideFile); err != nil || string(data) != "keep outside" {
				t.Errorf("write changed outside file: %q, %v", data, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(retained)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			if err := reopened.Read("transaction.json", &got); err != nil || got != updated {
				t.Fatalf("reopened store differs: %+v, %v", got, err)
			}
		})
	}
}

func TestOpenCreatesOnlyPrivateLeaf(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "state")
	for _, existing := range []bool{false, true} {
		if existing {
			if err := os.Chmod(state, 0o777); err != nil {
				t.Fatal(err)
			}
		}
		store, err := Open(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Write("transaction.json", fixture{Version: 1}); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		for path, mode := range map[string]os.FileMode{parent: 0o755, state: 0o700, filepath.Join(state, "transaction.json"): 0o600} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				t.Fatalf("%s: mode=%04o want=%04o", path, info.Mode().Perm(), mode)
			}
		}
	}
	missingParent := filepath.Join(parent, "missing")
	if store, err := Open(filepath.Join(missingParent, "state")); err == nil {
		_ = store.Close()
		t.Fatal("missing parent accepted")
	}
	if _, err := os.Lstat(missingParent); !os.IsNotExist(err) {
		t.Fatalf("Open created or failed to inspect missing ancestor: %v", err)
	}
}

func TestFailedWriteCleansRetainedDirectory(t *testing.T) {
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	store, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	retained := filepath.Join(parent, "retained")
	if err := os.Rename(state, retained); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(retained, "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "blocked")
	if err := os.WriteFile(outsideFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Write("blocked", fixture{}); !errors.Is(err, unix.EISDIR) {
		t.Fatalf("expected rename failure at retained directory: %v", err)
	}
	for _, directory := range []string{retained, outside} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != "blocked" {
			t.Fatalf("unexpected entries after failed publication: %s: %v", directory, entries)
		}
	}
	if data, err := os.ReadFile(outsideFile); err != nil || string(data) != "keep" {
		t.Fatalf("failure changed outside content: %q, %v", data, err)
	}
}

func TestTemporaryCreationRejectsCollisionsAndEntropyFailure(t *testing.T) {
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	store, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	collision := ".state-" + strings.Repeat("0", 32)
	if err := os.Symlink(outside, filepath.Join(state, collision)); err != nil {
		t.Fatal(err)
	}
	prior := rand.Reader
	t.Cleanup(func() { rand.Reader = prior })
	// The first generated name collides with a symlink; the second is fresh.
	rand.Reader = bytes.NewReader(append(make([]byte, 16), bytes.Repeat([]byte{1}, 16)...))
	want := fixture{Version: 1, Name: "collision retry"}
	if err := store.Write("transaction.json", want); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("temporary collision changed outside content: %q, %v", data, err)
	}
	rand.Reader = bytes.NewReader(nil)
	if err := store.Write("transaction.json", fixture{}); !errors.Is(err, io.EOF) {
		t.Fatalf("entropy failure not propagated: %v", err)
	}
	var got fixture
	if err := store.Read("transaction.json", &got); err != nil || got != want {
		t.Fatalf("failed write changed existing state: %+v, %v", got, err)
	}
	entries, err := os.ReadDir(state)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unexpected temporary entries: %v, %v", entries, err)
	}
}
