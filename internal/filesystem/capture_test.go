package filesystem

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

func TestCaptureRegularUsesOpenTimeBoundAcrossGrowthAndTruncation(t *testing.T) {
	t.Run("growth is deferred", func(t *testing.T) {
		rootPath := t.TempDir()
		path := filepath.Join(rootPath, "file")
		original := []byte("open-time bytes")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./file")
		defer root.Close()
		root.captureOpened = func(string) error {
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.WriteString(" appended later")
			return joinClose(writeErr, file.Close())
		}
		captured := capturePlanned(t, root, planned)
		assertCapturedBytes(t, captured, original)
		if !captured.Changed || !strings.Contains(captured.Reason, "changed while") {
			t.Fatalf("growth was not reported as a warning-worthy mutation: %#v", captured)
		}
	})

	t.Run("truncation commits the shorter bytes read", func(t *testing.T) {
		rootPath := t.TempDir()
		path := filepath.Join(rootPath, "file")
		original := []byte("truncate this payload")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./file")
		defer root.Close()
		want := original[:8]
		root.captureOpened = func(string) error { return os.Truncate(path, int64(len(want))) }
		captured := capturePlanned(t, root, planned)
		assertCapturedBytes(t, captured, want)
		if !captured.Changed || !strings.Contains(captured.Reason, "changed while") {
			t.Fatalf("truncation was not reported as a warning-worthy mutation: %#v", captured)
		}
	})
}

func TestCapturePathAcceptsSupportedTypeChangesAndOmitsSpecials(t *testing.T) {
	t.Run("regular becomes symlink", func(t *testing.T) {
		rootPath := t.TempDir()
		if err := os.WriteFile(filepath.Join(rootPath, "target"), []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(rootPath, "changing")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./changing")
		defer root.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target", path); err != nil {
			t.Fatal(err)
		}
		spool, err := PrepareSpool(t.TempDir(), "spool")
		if err != nil {
			t.Fatal(err)
		}
		defer spool.CloseAndRemove()
		captured, err := root.CapturePath(planned, spool, 1)
		if err != nil {
			t.Fatal(err)
		}
		if captured.Entry == nil || captured.Entry.Kind != format.KindSymlink || captured.Entry.Ref != "target:./target" || !captured.Changed {
			t.Fatalf("regular-to-symlink capture=%#v", captured)
		}
	})

	t.Run("symlink becomes regular", func(t *testing.T) {
		rootPath := t.TempDir()
		if err := os.WriteFile(filepath.Join(rootPath, "target"), []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(rootPath, "changing")
		if err := os.Symlink("target", path); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./changing")
		defer root.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		want := []byte("new regular")
		if err := os.WriteFile(path, want, 0o640); err != nil {
			t.Fatal(err)
		}
		captured := capturePlanned(t, root, planned)
		assertCapturedBytes(t, captured, want)
		if captured.Entry.Kind != format.KindFile || captured.Entry.Mode != 0o640 || !captured.Changed {
			t.Fatalf("symlink-to-regular capture=%#v", captured)
		}
	})

	t.Run("regular replaced between classification and open", func(t *testing.T) {
		rootPath := t.TempDir()
		path := filepath.Join(rootPath, "changing")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./changing")
		defer root.Close()
		want := []byte("replacement bytes")
		root.captureBeforeOpen = func(string) error {
			root.captureBeforeOpen = nil
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.WriteFile(path, want, 0o640)
		}
		captured := capturePlanned(t, root, planned)
		assertCapturedBytes(t, captured, want)
		if captured.Entry.Mode != 0o640 || !captured.Changed {
			t.Fatalf("replacement capture=%#v", captured)
		}
	})

	t.Run("planned leaf becomes special", func(t *testing.T) {
		rootPath := t.TempDir()
		path := filepath.Join(rootPath, "changing")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, planned := openPlannedPath(t, rootPath, "./changing")
		defer root.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		spool, err := PrepareSpool(t.TempDir(), "spool")
		if err != nil {
			t.Fatal(err)
		}
		defer spool.CloseAndRemove()
		captured, err := root.CapturePath(planned, spool, 1)
		if err != nil {
			t.Fatal(err)
		}
		if captured.Entry != nil || !captured.Changed || !strings.Contains(captured.Reason, "unsupported") {
			t.Fatalf("special capture=%#v", captured)
		}
	})
}

func openPlannedPath(t *testing.T, rootPath, wanted string) (*Root, format.IndexEntry) {
	t.Helper()
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanForTest(root, format.Ignore{}, nil)
	if err != nil {
		root.Close()
		t.Fatal(err)
	}
	for _, entry := range result.Index {
		if entry.Path == wanted {
			return root, entry
		}
	}
	root.Close()
	t.Fatalf("planned path %s not found in %#v", wanted, result.Index)
	return nil, format.IndexEntry{}
}

func capturePlanned(t *testing.T, root *Root, planned format.IndexEntry) CaptureResult {
	t.Helper()
	spool, err := PrepareSpool(t.TempDir(), "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.CloseAndRemove() })
	captured, err := root.CapturePath(planned, spool, 1)
	if err != nil {
		t.Fatal(err)
	}
	return captured
}

func assertCapturedBytes(t *testing.T, captured CaptureResult, want []byte) {
	t.Helper()
	if captured.Entry == nil || captured.Plain == nil {
		t.Fatalf("capture lacks regular bytes: %#v", captured)
	}
	defer captured.Plain.Remove()
	if _, err := captured.Plain.File.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(captured.Plain.File)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) || captured.Entry.Size != uint64(len(want)) {
		t.Fatalf("captured bytes=%q size=%d, want %q", got, captured.Entry.Size, want)
	}
	digest := blake2b.Sum512(want)
	if captured.Entry.Ref != fmt.Sprintf("blake2b:%x", digest[:]) {
		t.Fatalf("captured ref=%s", captured.Entry.Ref)
	}
}

func joinClose(operation, closeErr error) error {
	if operation != nil {
		return operation
	}
	return closeErr
}
