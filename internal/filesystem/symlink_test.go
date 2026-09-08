package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

func TestSymlinkPreservesLiveDeletedSuffix(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(strconv.FormatBool(directory), func(t *testing.T) {
			rootPath := t.TempDir()
			target := "target (deleted)"
			if directory {
				mustMkdir(t, filepath.Join(rootPath, target))
			} else {
				mustWrite(t, filepath.Join(rootPath, target), []byte("live"), 0o600)
			}
			if err := os.Symlink(target, filepath.Join(rootPath, "link")); err != nil {
				t.Fatal(err)
			}
			root, err := OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			want := format.IndexEntry{Path: "./link", Kind: format.KindSymlink, Ref: "target:./" + target}
			found := false
			_, err = root.Walk(format.Ignore{}, nil, func(_ *File, entry format.IndexEntry) error {
				if entry.Path == want.Path {
					found = true
					if entry != want {
						t.Errorf("walk entry=%#v, want %#v", entry, want)
					}
				}
				return nil
			})
			if err != nil || !found {
				t.Errorf("walk found link=%t err=%v", found, err)
			}
			captured := capturePlanned(t, root, want)
			if captured.Entry == nil || *captured.Entry != want || captured.Changed {
				t.Fatalf("capture=%#v, want unchanged %#v", captured, want)
			}
		})
	}
}

func TestSymlinkInvalidCanonicalTargetIsFatal(t *testing.T) {
	for _, name := range []string{"bad\tname", "bad\nname", "bad\rname", "bad\xffname"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			rootPath := t.TempDir()
			mustMkdir(t, filepath.Join(rootPath, "targets"))
			mustWrite(t, filepath.Join(rootPath, "targets", name), nil, 0o600)
			if err := os.Symlink("targets/"+name, filepath.Join(rootPath, "link")); err != nil {
				t.Fatal(err)
			}
			root, err := OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			// Prune the directory so only symlink-target validation sees the bad name.
			ignore, err := format.ParseIgnore(strings.NewReader("^\\./targets$\n"), format.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			_, err = root.Walk(ignore, nil, func(_ *File, _ format.IndexEntry) error { return nil })
			if err == nil || !strings.Contains(err.Error(), "invalid source symlink target") {
				t.Errorf("walk must fail canonical target validation, got %v", err)
			}
			spool, err := PrepareSpool(t.TempDir(), "spool")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = spool.CloseAndRemove() }()
			planned := format.IndexEntry{Path: "./link", Kind: format.KindSymlink, Ref: "target:./targets/old"}
			_, err = root.CapturePath(planned, spool, 1)
			if err == nil || !strings.Contains(err.Error(), "invalid source symlink target") {
				t.Errorf("capture must fail canonical target validation, got %v", err)
			}
		})
	}
}

func TestSymlinkClassificationRaceClosesTargetDescriptor(t *testing.T) {
	rootPath := t.TempDir()
	target := filepath.Join(rootPath, "target")
	mustWrite(t, target, nil, 0o600)
	link := filepath.Join(rootPath, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var before, targetStat unix.Stat_t
	if err := unix.Fstatat(root.fd, "link", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(target, &targetStat); err != nil {
		t.Fatal(err)
	}
	// Keep the original inode alive so the replacement cannot reuse its number.
	if err := os.Rename(link, link+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		_, _, err := root.scanSymlink(root.fd, "link", "./link", before)
		if !errors.Is(err, errCaptureRace) {
			t.Fatalf("expected classification race, got %v", err)
		}
	}
	// Inspect only this test's target inode, not fluctuating process-wide counts.
	// Close leaks after recording them so a failing regression leaves no residue.
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	leaks := 0
	for _, entry := range fds {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) == nil && stat.Dev == targetStat.Dev && stat.Ino == targetStat.Ino {
			leaks++
			_ = unix.Close(fd)
		}
	}
	if leaks != 0 {
		t.Fatalf("classification races leaked %d target descriptors", leaks)
	}
}

func TestSymlinkTargetMutationUsesDescriptorEvidence(t *testing.T) {
	for _, mutation := range []string{"unlink", "unlink-with-hardlink", "replace-same-inode", "replace-new-inode", "remove-directory"} {
		for _, capture := range []bool{false, true} {
			t.Run(mutation+"/capture="+strconv.FormatBool(capture), func(t *testing.T) {
				rootPath := t.TempDir()
				target := filepath.Join(rootPath, "target")
				if mutation == "remove-directory" {
					mustMkdir(t, target)
				} else {
					mustWrite(t, target, []byte("old"), 0o600)
				}
				// This live alias deliberately has the same printable proc-fd name
				// and inode as an unlinked target. Neither suffix nor nlink alone
				// can distinguish the deleted dentry from this surviving hardlink.
				alias := target + " (deleted)"
				if mutation == "unlink-with-hardlink" || mutation == "replace-same-inode" {
					if err := os.Link(target, alias); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("target", filepath.Join(rootPath, "link")); err != nil {
					t.Fatal(err)
				}
				root, planned := openPlannedPath(t, rootPath, "./link")
				defer func() { _ = root.Close() }()
				root.symlinkOpened = func() error {
					root.symlinkOpened = nil
					if err := os.Remove(target); err != nil {
						return err
					}
					switch mutation {
					case "replace-same-inode":
						return os.Link(alias, target)
					case "replace-new-inode":
						return os.WriteFile(target, []byte("new"), 0o600)
					}
					return nil
				}
				if !capture {
					var before unix.Stat_t
					if err := unix.Fstatat(root.fd, "link", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
						t.Fatal(err)
					}
					entry, _, err := root.scanSymlink(root.fd, "link", "./link", before)
					if !errors.Is(err, errCaptureRace) || entry != nil {
						t.Fatalf("target race accepted: entry=%#v err=%v", entry, err)
					}
					return
				}
				result := capturePlanned(t, root, planned)
				if strings.HasPrefix(mutation, "replace-") {
					if result.Entry == nil || *result.Entry != planned {
						t.Fatalf("retry did not capture current live target: %#v", result)
					}
				} else if result.Entry != nil || !result.Changed || !strings.Contains(result.Reason, "omitted") {
					t.Fatalf("retry did not omit now-broken link: %#v", result)
				}
			})
		}
	}
}
