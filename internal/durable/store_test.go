package durable

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fixture struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
}

func TestStoreRoundTripAndStrictSchema(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("transaction.json", fixture{Version: 1, Name: "x"}); err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := store.Read("transaction.json", &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Name != "x" {
		t.Fatalf("got=%#v", got)
	}
	if err := os.WriteFile(filepath.Join(store.Directory(), "transaction.json"), []byte(`{"version":1,"name":"x","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Read("transaction.json", &got); err == nil {
		t.Fatal("unknown JSON field accepted")
	}
}

func TestStoreRejectsUnsafeNamesAndTypes(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../escape", "a/b", ".", "-x"} {
		if err := store.Write(name, fixture{}); err == nil {
			t.Fatalf("unsafe name %q accepted", name)
		}
	}
	if err := os.Symlink("missing", filepath.Join(store.Directory(), "link")); err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := store.Read("link", &got); err == nil {
		t.Fatal("symlink state accepted")
	}
}

func TestStoreResetRemovesOnlyPrivateState(t *testing.T) {
	parent := t.TempDir()
	store, err := Open(filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("x.json", fixture{}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(store.Directory(), "nested", "deeper")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "state"), []byte("remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store.Directory(), "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := store.Reset(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "keep" {
		t.Fatalf("reset changed outside file: data=%q err=%v", data, err)
	}
	entries, err := os.ReadDir(store.Directory())
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
}

func TestStoreResetRejectsUnexpectedEntryType(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	fifo := filepath.Join(store.Directory(), "unexpected")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reset(); err == nil || !strings.Contains(err.Error(), "unexpected durable state entry type") {
		t.Fatalf("unexpected durable entry was accepted: %v", err)
	}
}
