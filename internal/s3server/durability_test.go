package s3server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDirectoryOpenRequiresParentDurability(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "observed-existing"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if existing {
				// This models a different request's mkdir becoming visible before
				// that request has completed its parent-directory fsync.
				if err := os.Mkdir(filepath.Join(root, "child"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// O_PATH permits descriptor-relative lookup/creation but not fsync.
			// This injects a real syscall failure, not a replacement filesystem.
			parent, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(parent) }()
			child, err := openOrCreateDirectory(parent, "child", 0o700)
			if child >= 0 {
				_ = unix.Close(child)
			}
			if !errors.Is(err, unix.EBADF) || child >= 0 {
				t.Fatalf("directory became usable without a successful parent fsync: fd=%d err=%v", child, err)
			}
			// A failed barrier leaves the directory intact. A fresh attempt must
			// establish durability through the existing-directory path.
			healthyParent, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(healthyParent) }()
			child, err = openOrCreateDirectory(healthyParent, "child", 0o700)
			if err != nil {
				t.Fatalf("retry parent barrier: %v", err)
			}
			if err := unix.Close(child); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstallCannotPublishThroughAnUnflushedAncestor(t *testing.T) {
	h := newHarness(t)
	body := []byte("publication must establish directory ancestry")
	key := objectKey(body, 9)
	components, err := keyComponents(key)
	if err != nil {
		t.Fatal(err)
	}
	parentPath := filepath.Join(append([]string{h.root}, components[:len(components)-1]...)...)
	if err := os.MkdirAll(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	name, file, err := createTemporaryFile(h.server.tempFD)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Unlinkat(h.server.tempFD, name, 0) }()
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	parent, err := unix.Open(h.root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(parent) }()
	// The payload and final parent directory can both be fsynced. Only the
	// ancestor barrier fails, which must prevent publication of the final key.
	publishing := &Server{rootFD: parent, tempFD: h.server.tempFD}
	if err := publishing.installTemporary(name, key); !errors.Is(err, unix.EBADF) {
		t.Fatalf("install ignored ancestor durability failure: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(h.root, filepath.FromSlash(key))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed ancestor barrier published an object: %v", err)
	}
	if err := h.server.installTemporary(name, key); err != nil {
		t.Fatalf("retry durable installation: %v", err)
	}
}

func TestServerRootRequiresParentDurability(t *testing.T) {
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
			root := filepath.Join(parent, "data")
			if existing {
				if err := os.Mkdir(root, 0o700); err != nil {
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
			// The parent allows child creation and lookup but cannot be opened
			// for its durability barrier. A trailing slash must not select data
			// itself as the containing parent.
			config := Config{Root: root + string(os.PathSeparator), Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}}
			server, err := Open(config)
			if server != nil {
				_ = server.Close()
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("server became ready without parent durability: %v", err)
			}
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			server, err = Open(config)
			if err != nil {
				t.Fatalf("retry server-root barrier: %v", err)
			}
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
