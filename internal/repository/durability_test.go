package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHardenedGitPinsDurability(t *testing.T) {
	directory := initTestRepo(t, "sha256")
	runGitTest(t, directory, "config", "core.fsync", "none")
	runGitTest(t, directory, "config", "core.fsyncMethod", "writeout-only")
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "core.fsync")
	t.Setenv("GIT_CONFIG_VALUE_0", "none")
	t.Setenv("GIT_CONFIG_KEY_1", "core.fsyncMethod")
	t.Setenv("GIT_CONFIG_VALUE_1", "writeout-only")
	repo := &Managed{Directory: directory}
	for key, expected := range map[string]string{"core.fsync": "objects,reference", "core.fsyncMethod": "fsync"} {
		output, err := repo.RunGit(nil, 1024, "config", "--get", key)
		if err != nil || strings.TrimSpace(string(output)) != expected {
			t.Errorf("%s = %q, err=%v; want %q", key, output, err, expected)
		}
	}
}

// Trace2 observes Git's own hardware-flush counter, not just config strings.
// This is not a power-loss simulation or a guarantee about storage hardware.
func TestHardenedGitFlushesLooseObjectsAndReferences(t *testing.T) {
	directory := initTestRepo(t, "sha256")
	runGitTest(t, directory, "config", "core.fsync", "none")
	runGitTest(t, directory, "config", "core.fsyncMethod", "writeout-only")
	run := func(input string, arguments ...string) string {
		t.Helper()
		trace := filepath.Join(t.TempDir(), "trace.jsonl")
		command, err := hardenedGitCommand(directory, arguments...)
		if err != nil {
			t.Fatal(err)
		}
		command.Env = append(command.Env, "GIT_TRACE2_EVENT="+trace)
		command.Stdin = strings.NewReader(input)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil || stderr.Len() != 0 {
			t.Fatalf("git %s: %v, %s", arguments[0], err, stderr.String())
		}
		data, err := os.ReadFile(trace)
		if err != nil {
			t.Fatal(err)
		}
		flushed := false
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			var event struct {
				Category string `json:"category"`
				Name     string `json:"name"`
				Count    int    `json:"count"`
				Key      string `json:"key"`
				Value    string `json:"value"`
			}
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			if event.Category == "fsync" && event.Name == "hardware-flush" && event.Count > 0 {
				flushed = true
			}
			// Git 2.36 reports these as data events rather than counters.
			if event.Category == "fsync" && event.Key == "fsync/hardware-flush" {
				count, err := strconv.Atoi(event.Value)
				if err != nil {
					t.Fatal(err)
				}
				flushed = flushed || count > 0
			}
		}
		if !flushed {
			t.Errorf("git %s did not report a hardware flush: %s", arguments[0], data)
		}
		return strings.TrimSpace(string(output))
	}
	oid := run("durability regression\n", "hash-object", "-w", "--stdin")
	run("", "update-ref", "refs/backup/durability", oid)
}

func TestHardenedGitWriteFailureRemainsAnError(t *testing.T) {
	directory := initTestRepo(t, "sha256")
	repo := &Managed{Directory: directory}
	output, err := repo.RunGit([]byte("durability error test\n"), 1024, "hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	oid := strings.TrimSpace(string(output))
	// A real Git write failure (lock conflict), not an injected power failure.
	lock := filepath.Join(directory, ".git", "refs", "tags", "durability.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = repo.RunGit(nil, 1024, "update-ref", "refs/tags/durability", oid)
	var exit *GitExitError
	if !errors.As(err, &exit) || exit.ExitCode == 0 || exit.Operation != "update-ref" {
		t.Fatalf("write failure lost its exit status: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(lock, ".lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed update published ref: %v", err)
	}
}

func TestDurableGitCompatibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		script string
		wantOK bool
	}{
		{"minimum", "printf 'git version 2.36.0\\n'", true},
		{"vendor", "printf 'git version 2.55.0.vendor.1\\n'", true},
		{"future", "printf 'git version 3.0.0\\n'", true},
		{"old", "printf 'git version 2.35.9\\n'", false},
		{"old-major", "printf 'git version 1.99.0\\n'", false},
		{"malformed", "printf 'git version garbage\\n'", false},
		{"overflow", "printf 'git version 999999999999999999999999999999.0.0\\n'", false},
		{"failure", "printf 'git version 2.55.0\\n'; exit 23", false},
		{"warning", "printf 'git version 2.55.0\\n'; printf 'warning\\n' >&2", false},
		{"bounded", "printf 'git version 2.55.0'; printf '%2048s' x", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			bin := t.TempDir()
			path := filepath.Join(bin, "git")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 99\n"+test.script+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			got, err := findDurableGit()
			if (err == nil) != test.wantOK || test.wantOK && got != path {
				t.Fatalf("executable=%q err=%v; wantOK=%v", got, err, test.wantOK)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := findDurableGit(); err == nil {
			t.Fatal("missing Git accepted")
		}
	})
}

func TestGitCompatibilityFailureStopsInitialization(t *testing.T) {
	// A fresh process exercises the real once-only preflight, independent of
	// whichever Git commands the rest of the package tests already executed.
	if destination := os.Getenv("BACKUP_TEST_OLD_GIT_DESTINATION"); destination != "" {
		err := InitializeBareSHA256(destination)
		if err == nil || !strings.Contains(err.Error(), "Git 2.36 or newer") {
			t.Fatalf("unsupported Git did not fail closed: %v", err)
		}
		if _, err := OpenManaged(t.TempDir(), "unused", "main"); err == nil || !strings.Contains(err.Error(), "Git 2.36 or newer") {
			t.Fatalf("open lost compatibility error: %v", err)
		}
		return
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'git version 2.35.0\\n'; exit 0; fi\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "must-not-exist.git")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestGitCompatibilityFailureStopsInitialization$")
	command.Env = append(os.Environ(), "PATH="+bin, "BACKUP_TEST_OLD_GIT_DESTINATION="+destination)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("preflight subprocess: %v: %s", err, output)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsupported Git initialized repository: %v", err)
	}
}
