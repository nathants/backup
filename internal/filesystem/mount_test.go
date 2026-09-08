package filesystem

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

func TestWalkMountReportingOrdinaryDirectories(t *testing.T) {
	rootPath := t.TempDir()
	mustMkdir(t, filepath.Join(rootPath, "nested"))
	mustWrite(t, filepath.Join(rootPath, "nested", "content"), []byte("content"), 0o600)
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	result, err := scanForTest(root, format.Ignore{}, func(event Event) {
		if event.Kind == EventMountEntered {
			t.Errorf("root or ordinary directory reported as a mount: %+v", event)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.MountsEntered != 0 || len(result.Index) != 1 {
		t.Fatalf("scan result: %+v", result)
	}
}

func TestScanMountDescriptorErrorIsFatal(t *testing.T) {
	root := &Root{fd: -1}
	var result Result
	err := root.scanDirectory(-1, "nested", 0, format.Ignore{}, nil, func(event Event) {
		t.Errorf("reported event after failed mount lookup: %+v", event)
	}, &result, func(_ *File, entry format.IndexEntry) error {
		t.Errorf("visited entry after failed mount lookup: %+v", entry)
		return nil
	})
	if !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), `stat source directory mount "./nested"`) {
		t.Fatalf("mount descriptor error: %v", err)
	}
}
