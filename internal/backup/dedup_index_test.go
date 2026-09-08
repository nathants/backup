package backup

import (
	"strings"
	"testing"
)

func TestDecodeOneJSONRejectsTrailingValue(t *testing.T) {
	var value struct {
		Value int `json:"value"`
	}
	if err := decodeOneJSON([]byte("{\"value\":1}\n{\"value\":2}\n"), &value); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if err := decodeOneJSON([]byte("{\"value\":1}\n"), &value); err != nil || value.Value != 1 {
		t.Fatalf("single JSON value: %#v %v", value, err)
	}
}

func TestDedupIndexStoresAndChecksHashAndSize(t *testing.T) {
	index, err := newDedupIndex(t.TempDir()+"/index", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = index.Close() }()

	first := strings.Repeat("01", 64)
	second := strings.Repeat("ab", 64)
	if err := index.Insert(first, 7); err != nil {
		t.Fatal(err)
	}
	if found, err := index.Contains(first, 7); err != nil || !found {
		t.Fatalf("contains first=%v err=%v", found, err)
	}
	if found, err := index.Contains(second, 9); err != nil || found {
		t.Fatalf("contains absent=%v err=%v", found, err)
	}
	if err := index.Insert(second, 9); err != nil {
		t.Fatal(err)
	}
	if err := index.Insert(first, 8); err == nil || !strings.Contains(err.Error(), "conflicting size") {
		t.Fatalf("conflicting size was accepted: %v", err)
	}
	if err := index.Insert(first, 7); err != nil {
		t.Fatalf("idempotent insertion: %v", err)
	}
}
