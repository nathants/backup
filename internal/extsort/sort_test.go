package extsort

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSortFilesUsesMultipleRunsAndRejectsDuplicateKeys(t *testing.T) {
	workspace := t.TempDir()
	first := filepath.Join(workspace, "first")
	second := filepath.Join(workspace, "second")
	if err := os.WriteFile(first, []byte("d\t4\nb\t2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("c\t3\na\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(workspace, "output")
	key := func(record []byte) ([]byte, error) { return bytes.SplitN(record, []byte{'\t'}, 2)[0], nil }
	if err := SortFiles(workspace, []string{first, second}, output, Options{MemoryBytes: 65, MaxOpenFiles: 2, Unique: true, Key: key}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "a\t1\nb\t2\nc\t3\nd\t4\n" {
		t.Fatalf("sorted output=%q err=%v", data, err)
	}

	duplicate := filepath.Join(workspace, "duplicate")
	if err := os.WriteFile(duplicate, []byte("b\tother\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SortFiles(workspace, []string{first, duplicate}, filepath.Join(workspace, "duplicate-output"), Options{MemoryBytes: 65, MaxOpenFiles: 2, Unique: true, Key: key}); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key was accepted: %v", err)
	}
}

func TestSortFilesRequiresCanonicalLineTermination(t *testing.T) {
	workspace := t.TempDir()
	input := filepath.Join(workspace, "input")
	if err := os.WriteFile(input, []byte("missing LF"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SortFiles(workspace, []string{input}, filepath.Join(workspace, "output"), Options{}); err == nil || !strings.Contains(err.Error(), "does not end in LF") {
		t.Fatalf("unterminated input was accepted: %v", err)
	}
}
