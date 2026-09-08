package repository

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportPackStreamsVerifiedObjectsAndRejectsMalformedInput(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "source.git")
	if err := InitializeBareSHA256(sourcePath); err != nil {
		t.Fatal(err)
	}
	source := &Managed{Directory: sourcePath}
	content := []byte("native Git pack fixture")
	object, err := source.RunGit(content, 1024, "hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	packed, err := source.RunGit(object, 64<<10, "pack-objects", "--stdout")
	if err != nil {
		t.Fatal(err)
	}
	badChecksum := append([]byte(nil), packed...)
	badChecksum[len(badChecksum)-1] ^= 1
	for _, test := range []struct {
		name  string
		input io.Reader
		valid bool
	}{
		{"valid", bytes.NewReader(packed), true},
		{"nil", nil, false},
		{"empty", bytes.NewReader(nil), false},
		{"truncated", bytes.NewReader(packed[:len(packed)-1]), false},
		{"wrong checksum", bytes.NewReader(badChecksum), false},
		{"trailing bytes", bytes.NewReader(append(append([]byte(nil), packed...), []byte("trailing bytes")...)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "import.git")
			if err := InitializeBareSHA256(path); err != nil {
				t.Fatal(err)
			}
			repo := &Managed{Directory: path}
			err := repo.ImportPack(test.input)
			if !test.valid {
				if err == nil {
					t.Fatal("malformed pack import succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.ImportPack(bytes.NewReader(packed)); err != nil {
				t.Fatalf("identical pack retry failed: %v", err)
			}
			got, err := repo.RunGit(nil, 1024, "cat-file", "blob", strings.TrimSpace(string(object)))
			if err != nil || !bytes.Equal(got, content) {
				t.Fatalf("imported content=%q err=%v", got, err)
			}
		})
	}
}
