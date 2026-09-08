package filesystem

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

func TestScanPreservesSymlinkToBackupRoot(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Symlink(".", filepath.Join(rootPath, "root-link")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	result, err := scanForTest(root, format.Ignore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Index) != 1 || result.Index[0].Path != "./root-link" || result.Index[0].Kind != format.KindSymlink || result.Index[0].Ref != "target:./" {
		t.Fatalf("root symlink was not preserved canonically: %#v", result.Index)
	}
	data, err := format.MarshalIndex(result.Index)
	if err != nil {
		t.Fatalf("canonical root symlink metadata was rejected: %v", err)
	}
	parsed, err := format.ParseIndex(bytes.NewReader(data), format.DefaultLimits())
	if err != nil || len(parsed) != 1 || parsed[0] != result.Index[0] {
		t.Fatalf("root symlink metadata round trip=%#v err=%v", parsed, err)
	}
}

func TestScanFilesSymlinksIgnoresAndSpecials(t *testing.T) {
	rootPath := t.TempDir()
	mustMkdir(t, filepath.Join(rootPath, "dir"))
	mustWrite(t, filepath.Join(rootPath, "dir", "file with space"), []byte("alpha"), 0o640)
	mustWrite(t, filepath.Join(rootPath, "unicode-π"), []byte("beta"), 0o600)
	mustMkdir(t, filepath.Join(rootPath, "ignored"))
	mustWrite(t, filepath.Join(rootPath, "ignored", "secret"), []byte("secret"), 0o600)
	mustMkdir(t, filepath.Join(rootPath, ".backup"))
	mustWrite(t, filepath.Join(rootPath, ".backup", "internal"), []byte("no"), 0o600)
	if err := os.Symlink("dir/file with space", filepath.Join(rootPath, "file-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir", filepath.Join(rootPath, "dir-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(rootPath, "broken")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	mustWrite(t, outside, []byte("outside"), 0o600)
	if err := os.Symlink(outside, filepath.Join(rootPath, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(rootPath, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	ignore, err := format.ParseIgnore(strings.NewReader(`^\./ignored(?:/|$)`+"\n"), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var events []Event
	result, err := scanForTest(root, ignore, func(event Event) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}

	byPath := make(map[string]format.IndexEntry)
	for _, entry := range result.Index {
		byPath[entry.Path] = entry
	}
	if len(byPath) != 4 {
		t.Fatalf("unexpected index: %#v", result.Index)
	}
	file := byPath["./dir/file with space"]
	if file.Kind != format.KindFile || file.Size != 5 || file.Mode != 0o640 || !strings.HasPrefix(file.Ref, "blake2b:") {
		t.Fatalf("bad file metadata: %#v", file)
	}
	if byPath["./file-link"].Ref != "target:./dir/file with space" {
		t.Fatalf("bad file link: %#v", byPath["./file-link"])
	}
	if byPath["./dir-link"].Ref != "target:./dir" {
		t.Fatalf("bad directory link: %#v", byPath["./dir-link"])
	}
	if _, ok := byPath["./dir-link/file with space"]; ok {
		t.Fatal("scanner followed a directory symlink")
	}
	if len(result.Files) != 2 {
		t.Fatalf("files=%#v", result.Files)
	}
	if result.SkippedBrokenSymlinks != 1 || result.SkippedOutsideSymlinks != 1 || result.SkippedSpecial != 1 {
		t.Fatalf("skip counts: %#v events=%#v", result, events)
	}
	for path := range byPath {
		if strings.HasPrefix(path, "./ignored") || strings.HasPrefix(path, "./.backup") {
			t.Fatalf("excluded path was indexed: %q", path)
		}
	}
}

func TestScanUsesActualAbsoluteSymlinkSemantics(t *testing.T) {
	rootPath := t.TempDir()
	mustWrite(t, filepath.Join(rootPath, "inside"), []byte("inside"), 0o600)
	mustMkdir(t, filepath.Join(rootPath, "etc"))
	mustWrite(t, filepath.Join(rootPath, "etc", "passwd"), []byte("decoy"), 0o600)
	if err := os.Symlink(filepath.Join(rootPath, "inside"), filepath.Join(rootPath, "absolute-inside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(rootPath, "absolute-outside")); err != nil {
		t.Fatal(err)
	}

	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	result, err := scanForTest(root, format.Ignore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	byPath := make(map[string]format.IndexEntry)
	for _, entry := range result.Index {
		byPath[entry.Path] = entry
	}
	if got := byPath["./absolute-inside"].Ref; got != "target:./inside" {
		t.Fatalf("absolute in-root symlink target = %q", got)
	}
	if _, ok := byPath["./absolute-outside"]; ok {
		t.Fatal("absolute outside symlink was redirected into a same-named in-root path")
	}
	if result.SkippedOutsideSymlinks != 1 {
		t.Fatalf("outside skips = %d", result.SkippedOutsideSymlinks)
	}
}

func TestWalkReadsAllDirectoryBatches(t *testing.T) {
	rootPath := t.TempDir()
	for index := 0; index < 300; index++ {
		mustWrite(t, filepath.Join(rootPath, fmt.Sprintf("file-%03d", index)), nil, 0o600)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	result, err := scanForTest(root, format.Ignore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 300 || len(result.Index) != 300 {
		t.Fatalf("entries=%d index=%d, want 300", result.Entries, len(result.Index))
	}
}

func TestScanRejectsInvalidPathAndReadFailure(t *testing.T) {
	rootPath := t.TempDir()
	mustWrite(t, filepath.Join(rootPath, "bad\tname"), []byte("x"), 0o600)
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := scanForTest(root, format.Ignore{}, nil); err == nil {
		t.Fatal("invalid path was silently omitted")
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
