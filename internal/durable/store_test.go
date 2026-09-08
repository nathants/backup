package durable

import (
	"os"
	"path/filepath"
	"testing"
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
	t.Cleanup(func() { _ = store.Close() })
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
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
}

func TestStoreRejectsUnsafeNamesAndTypes(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
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
