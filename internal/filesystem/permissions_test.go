package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestWalkSkipsPermissionDeniedSources(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, kind := range []string{"file", "unreadable-directory", "unsearchable-directory", "symlink-target"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			mustWrite(t, filepath.Join(path, "keep"), []byte("readable"), 0600)
			denied := filepath.Join(path, "denied")
			mode := os.FileMode(0000)
			switch kind {
			case "file":
				mustWrite(t, denied, []byte("unreadable"), 0600)
			case "unreadable-directory", "unsearchable-directory":
				mustMkdir(t, denied)
				mustWrite(t, filepath.Join(denied, "hidden"), []byte("unreadable"), 0600)
				if kind == "unsearchable-directory" {
					mode = 0400
				}
			case "symlink-target":
				parent := filepath.Join(t.TempDir(), "private")
				mustMkdir(t, parent)
				mustWrite(t, filepath.Join(parent, "target"), []byte("inaccessible"), 0600)
				if err := os.Symlink(filepath.Join(parent, "target"), denied); err != nil {
					t.Fatal(err)
				}
				denied = parent
			}
			denySourceAccess(t, denied, mode)
			root, err := OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			var events []Event
			result, err := scanForTest(root, format.Ignore{}, func(event Event) { events = append(events, event) })
			if err != nil {
				t.Fatalf("source permission denial stopped the scan: %v", err)
			}
			if result.Entries != 1 || len(result.Index) != 1 || result.Index[0].Path != "./keep" || result.SkippedPermissionDenied != 1 {
				t.Fatalf("scan included an inaccessible source or omitted readable content: %+v", result)
			}
			if len(events) != 1 || events[0].Kind != EventPermissionSkipped || events[0].Path != "./denied" || !strings.Contains(events[0].Detail, "permission denied") {
				t.Fatalf("missing exact permission warning: %+v", events)
			}
			info, err := os.Stat(denied)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("source permissions were changed: %v, %v", info, err)
			}
		})
	}
}

func TestCaptureSkipsPermissionDeniedSources(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	for _, kind := range []string{"file", "parent", "symlink-target"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			parent := filepath.Join(path, "parent")
			mustMkdir(t, parent)
			file := filepath.Join(parent, "file")
			mustWrite(t, file, []byte("add-time bytes"), 0600)
			selected, denied := "./parent/file", file
			if kind == "parent" {
				denied = parent
			}
			if kind == "symlink-target" {
				if err := os.Symlink("parent/file", filepath.Join(path, "link")); err != nil {
					t.Fatal(err)
				}
				selected, denied = "./link", parent
			}
			root, planned := openPlannedPath(t, path, selected)
			defer func() { _ = root.Close() }()
			denySourceAccess(t, denied, 0000)
			spool, err := PrepareSpool(t.TempDir(), "spool")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = spool.CloseAndRemove() }()
			captured, err := root.CapturePath(planned, spool, 1)
			if err != nil {
				t.Fatalf("source permission denial stopped capture: %v", err)
			}
			if captured.Entry != nil || captured.Plain != nil || !captured.Changed || !strings.Contains(captured.Reason, "permission denied") || !strings.Contains(captured.Reason, "omitted") {
				t.Fatalf("inaccessible source was not omitted with a warning: %+v", captured)
			}
			entries, err := os.ReadDir(spool.Path())
			if err != nil || len(entries) != 0 {
				t.Fatalf("skipped capture retained plaintext: %v, %v", entries, err)
			}
		})
	}
}

func TestWalkSkipsBrokenSymlinkTargets(t *testing.T) {
	for _, target := range []string{"missing", "keep/not-a-directory", "link"} {
		t.Run(target, func(t *testing.T) {
			path := t.TempDir()
			mustWrite(t, filepath.Join(path, "keep"), []byte("readable"), 0600)
			if err := os.Symlink(target, filepath.Join(path, "link")); err != nil {
				t.Fatal(err)
			}
			root, err := OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			var events []Event
			result, err := scanForTest(root, format.Ignore{}, func(event Event) { events = append(events, event) })
			if err != nil {
				t.Fatal(err)
			}
			if result.Entries != 1 || result.SkippedBrokenSymlinks != 1 || len(events) != 1 || events[0].Kind != EventBrokenSymlink || events[0].Path != "./link" {
				t.Fatalf("broken link was not skipped with a diagnostic: %+v, %+v", result, events)
			}
		})
	}
}

func TestCaptureSpoolPermissionFailureRemainsFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires permission enforcement")
	}
	path := t.TempDir()
	mustWrite(t, filepath.Join(path, "file"), []byte("readable"), 0600)
	root, planned := openPlannedPath(t, path, "./file")
	defer func() { _ = root.Close() }()
	spool, err := PrepareSpool(t.TempDir(), "spool")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.CloseAndRemove() })
	denySourceAccess(t, spool.Path(), 0500)
	if _, err := root.CapturePath(planned, spool, 1); err == nil {
		t.Fatal("plaintext staging permission failure was hidden as a source skip")
	}
}

func denySourceAccess(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, info.Mode().Perm()); err != nil {
			t.Error(err)
		}
	})
}
