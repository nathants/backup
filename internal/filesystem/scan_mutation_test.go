package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

func TestScanRegularUsesBoundedProvisionalObservation(t *testing.T) {
	mtime := time.Unix(1_700_000_000, 123_456_789)
	appendLater := func(path string) error {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString(" appended later")
		return joinClose(writeErr, file.Close())
	}
	for _, test := range []struct {
		name     string
		original string
		want     string
		mutate   func(string) error
	}{
		{name: "stable", original: "initial bytes", want: "initial bytes"},
		{name: "growth is deferred", original: "initial bytes", want: "initial bytes", mutate: appendLater},
		{name: "empty file growth is deferred", mutate: appendLater},
		{
			name: "truncation uses actual size", original: "initial bytes", want: "initial",
			mutate: func(path string) error { return os.Truncate(path, int64(len("initial"))) },
		},
		{
			name: "truncation to empty retains the path", original: "initial bytes",
			mutate: func(path string) error { return os.Truncate(path, 0) },
		},
		{
			name: "in-place change uses bytes read", original: "initial bytes", want: "changed bytes",
			mutate: func(path string) error {
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				_, writeErr := file.WriteAt([]byte("changed"), 0)
				return joinClose(writeErr, file.Close())
			},
		},
		{
			name: "metadata change retains open-time observation", original: "initial bytes", want: "initial bytes",
			mutate: func(path string) error {
				if err := os.Chmod(path, 0o600); err != nil {
					return err
				}
				return os.Chtimes(path, mtime.Add(time.Hour), mtime.Add(time.Hour))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			path := filepath.Join(rootPath, "file with space")
			mustWrite(t, path, []byte(test.original), 0o640)
			if err := os.Chtimes(path, mtime, mtime); err != nil {
				t.Fatal(err)
			}
			root, err := OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			opened := 0
			// Mutate the real source after its descriptor and initial metadata
			// are fixed, without depending on file size or scheduler timing.
			root.scanOpened = func(indexPath string) error {
				opened++
				if indexPath != "./file with space" {
					t.Fatalf("opened unexpected source %q", indexPath)
				}
				if test.mutate != nil {
					return test.mutate(path)
				}
				return nil
			}
			var events []Event
			scanned, err := scanForTest(root, format.Ignore{}, func(event Event) { events = append(events, event) })
			if err != nil {
				t.Fatalf("readable regular file failed provisional scan: %v", err)
			}
			if opened != 1 || scanned.Entries != 1 || len(scanned.Index) != 1 || len(scanned.Files) != 1 {
				t.Fatalf("scan retried or omitted the path: opened=%d result=%#v", opened, scanned)
			}
			digest := blake2b.Sum512([]byte(test.want))
			hash := fmt.Sprintf("%x", digest)
			want := format.IndexEntry{
				Path: "./file with space", Kind: format.KindFile, Ref: "blake2b:" + hash,
				Size: uint64(len(test.want)), Mode: 0o640, MtimeNS: mtime.UnixNano(),
			}
			if scanned.Index[0] != want || scanned.Files[0] != (File{Hash: hash, Size: want.Size}) {
				t.Fatalf("provisional index/hash rows disagree with bounded bytes: %#v; want %#v", scanned, want)
			}
			if test.mutate == nil {
				if len(events) != 0 {
					t.Fatalf("stable file emitted events: %#v", events)
				}
			} else if len(events) != 1 || events[0].Kind != "file-changed" || events[0].Path != want.Path || !strings.Contains(events[0].Detail, "changed while hashing") {
				t.Fatalf("source mutation warning was not reported: %#v", events)
			}

			// A later scan observes the current bytes, including any append
			// deferred by the first scan; it does not reuse the earlier hash.
			root.scanOpened = nil
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			events = nil
			repeated, err := scanForTest(root, format.Ignore{}, func(event Event) { events = append(events, event) })
			if err != nil {
				t.Fatal(err)
			}
			currentDigest := blake2b.Sum512(current)
			if len(repeated.Index) != 1 || repeated.Index[0].Ref != fmt.Sprintf("blake2b:%x", currentDigest) || repeated.Index[0].Size != uint64(len(current)) || len(events) != 0 {
				t.Fatalf("subsequent scan did not observe the current file: %#v events=%#v", repeated, events)
			}
		})
	}
}

func TestScanRegularStillRejectsUnsafeLeafChanges(t *testing.T) {
	for _, test := range []struct {
		name    string
		replace func(string) error
	}{
		{name: "different regular inode", replace: func(path string) error { return os.WriteFile(path, []byte("new inode"), 0o600) }},
		{name: "symlink", replace: func(path string) error { return os.Symlink("original", path) }},
		{name: "fifo", replace: func(path string) error { return unix.Mkfifo(path, 0o600) }},
		{name: "directory", replace: func(path string) error { return os.Mkdir(path, 0o700) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			path := filepath.Join(rootPath, "file")
			mustWrite(t, path, []byte("original bytes"), 0o600)
			root, err := OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			var classified unix.Stat_t
			if err := unix.Fstatat(root.fd, "file", &classified, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				t.Fatal(err)
			}
			// Retain the original inode so replacement cannot reuse its number.
			if err := os.Rename(path, filepath.Join(rootPath, "original")); err != nil {
				t.Fatal(err)
			}
			if err := test.replace(path); err != nil {
				t.Fatal(err)
			}
			root.scanOpened = func(string) error {
				t.Fatal("unsafe replacement reached hashing")
				return nil
			}
			_, _, err = root.scanRegular(root.fd, "file", "./file", classified, func(event Event) {
				t.Fatalf("unsafe replacement was downgraded to a warning: %#v", event)
			})
			if err == nil {
				t.Fatal("unsafe replacement was accepted")
			}
		})
	}
}
