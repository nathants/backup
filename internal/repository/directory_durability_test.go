package repository

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMetadataRootRequiresParentDurability(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read-permission failures")
	}
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			directory := filepath.Join(parent, ".backup")
			if existing {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(parent, 0o300); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(parent, 0o700); err != nil {
					t.Error(err)
				}
			})
			// Child creation and Git writes work; only the containing-directory
			// durability barrier is unavailable. It must fail before Git setup.
			if _, err := InitializeLocal(directory + string(os.PathSeparator)); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("metadata initialized without parent durability: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, ".git")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("parent barrier failure reached Git setup: %v", err)
			}
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := InitializeLocal(directory); err != nil {
				t.Fatalf("retry metadata-root barrier: %v", err)
			}
		})
	}
}

func TestDurableSetupParentsPreserveExistingNamespace(t *testing.T) {
	parent := t.TempDir()
	marker := filepath.Join(parent, "keep")
	if err := os.WriteFile(marker, []byte("existing data"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "parent-alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(alias, "new", "nested", ".backup")
	if _, err := InitializeLocal(directory); err != nil {
		t.Fatalf("initialize through trusted parent alias: %v", err)
	}
	for _, path := range []string{filepath.Join(parent, "new"), filepath.Join(parent, "new", "nested"), filepath.Join(parent, "new", "nested", ".backup")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("invalid created setup directory %s: %v %v", path, info, err)
		}
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "existing data" {
		t.Fatalf("initialization changed unrelated parent data: %q %v", data, err)
	}
	if err := makeDurableParents(filepath.Join(marker, "child")); err == nil {
		t.Fatal("regular-file setup ancestor accepted")
	}
}
