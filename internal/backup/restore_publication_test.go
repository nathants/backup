package backup

import (
	"errors"
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

func TestRestoreRegularPublicationRejectsChangedTemporaryEntry(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		for _, replacement := range []string{"unchanged", "symlink", "regular", "missing"} {
			t.Run(fmt.Sprintf("overwrite=%t/%s", overwrite, replacement), func(t *testing.T) {
				target := t.TempDir()
				rootFD, _, err := openTargetRoot(target)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = unix.Close(rootFD) }()
				destination := filepath.Join(target, "file")
				if overwrite {
					if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				before, err := os.Stat(outside)
				if err != nil {
					t.Fatal(err)
				}

				// A FIFO schedules the actual copy into the destination temp:
				// opening the writer succeeds only once publishRegular opens its
				// input, after creating the temp. No production test hook is used.
				source := filepath.Join(t.TempDir(), "source")
				if err := unix.Mkfifo(source, 0o600); err != nil {
					t.Fatal(err)
				}
				digest := blake2b.Sum512([]byte("payload"))
				entry := format.IndexEntry{
					Path: "./file", Kind: format.KindFile, Ref: fmt.Sprintf("blake2b:%x", digest),
					Size: 7, Mode: 0o640, MtimeNS: 1_700_000_000_123_456_789,
				}
				result := make(chan error, 1)
				go func() { result <- publishRegular(rootFD, source, entry, overwrite) }()
				writer := openRestoreTestWriter(t, source, result)
				defer func() { _ = writer.Close() }()

				entries, err := os.ReadDir(target)
				if err != nil {
					t.Fatal(err)
				}
				temporary := ""
				for _, candidate := range entries {
					if strings.HasPrefix(candidate.Name(), ".backup-restore-") {
						if temporary != "" {
							t.Fatal("multiple destination temporaries")
						}
						temporary = filepath.Join(target, candidate.Name())
					}
				}
				if temporary == "" {
					t.Fatal("copy began without a destination temporary")
				}
				if replacement != "unchanged" {
					if err := os.Remove(temporary); err != nil {
						t.Fatal(err)
					}
				}
				switch replacement {
				case "symlink":
					err = os.Symlink(outside, temporary)
				case "regular":
					err = os.WriteFile(temporary, []byte("unverified"), 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-result:
				case <-time.After(10 * time.Second):
					t.Fatal("publication did not finish after closing the source")
				}
				if replacement == "unchanged" {
					if err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(destination)
					if err != nil || string(data) != "payload" {
						t.Fatalf("published bytes=%q err=%v", data, err)
					}
					info, err := os.Stat(destination)
					if err != nil || info.Mode().Perm() != 0o640 || info.ModTime().UnixNano() != entry.MtimeNS {
						t.Fatalf("published metadata=%v err=%v", info, err)
					}
				} else {
					if err == nil {
						t.Error("substituted destination temporary was published successfully")
					}
					var marker interface{ Published() bool }
					if errors.As(err, &marker) && marker.Published() {
						t.Errorf("substitution was detected only after publication: %v", err)
					}
					if overwrite {
						data, err := os.ReadFile(destination)
						if err != nil || string(data) != "original" {
							t.Errorf("existing destination changed: bytes=%q err=%v", data, err)
						}
					} else if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("failed publication created destination: %v", err)
					}
				}
				after, err := os.Stat(outside)
				if err != nil {
					t.Fatal(err)
				}
				if !before.ModTime().Equal(after.ModTime()) {
					t.Errorf("outside file mtime changed to %d", after.ModTime().UnixNano())
				}
			})
		}
	}
}

func openRestoreTestWriter(t *testing.T, path string, result <-chan error) *os.File {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			return os.NewFile(uintptr(fd), path)
		}
		if !errors.Is(err, unix.ENXIO) {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			t.Fatalf("publication stopped before opening the source: %v", err)
		case <-timeout.C:
			t.Fatal("publication did not open the source")
		case <-tick.C:
		}
	}
}
