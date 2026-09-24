package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressSurvivesClosedStderrPipe(t *testing.T) {
	if root := os.Getenv("BACKUP_PROGRESS_PIPE_TEST_ROOT"); root != "" {
		os.Args = []string{"backup", "add", "--root", root}
		main()
		os.Exit(0)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := t.TempDir()
	if err := run(context.Background(), []string{"init", "--root", root}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestProgressSurvivesClosedStderrPipe$")
	command.Env = append(os.Environ(), "BACKUP_PROGRESS_PIPE_TEST_ROOT="+root)
	command.Stderr = writer
	output, err := command.Output()
	if err != nil || !strings.Contains(string(output), "entries\t1\n") {
		t.Fatalf("closed progress pipe hid the CLI result: output=%q err=%v", output, err)
	}
	records := readDebugLogs(t, home)
	diagnostics := recordedStream(records, "stderr")
	if recordedStream(records, "stdout") != string(output) || !strings.Contains(diagnostics, "progress: add:") {
		t.Fatalf("closed progress pipe lost disk diagnostics: %+v", records)
	}
	for _, want := range []string{"scanning source and building path plan", "selected paths=1 hashed files=1", "sorting and validating path plan"} {
		if !strings.Contains(diagnostics, want) {
			t.Fatalf("closed stderr stopped healthy disk progress before %q: %s", want, diagnostics)
		}
	}
}

type progressSinkFunc func([]byte) (int, error)

func (write progressSinkFunc) Write(data []byte) (int, error) { return write(data) }

func TestProgressDestinationsFailIndependently(t *testing.T) {
	for _, test := range []struct {
		name          string
		terminalFails bool
		terminalShort bool
		diskFails     bool
	}{
		{name: "healthy"},
		{name: "terminal-error", terminalFails: true},
		{name: "terminal-short-write", terminalFails: true, terminalShort: true},
		{name: "disk-error", diskFails: true},
		{name: "both-errors", terminalFails: true, diskFails: true},
		{name: "disk-error-and-terminal-short-write", terminalFails: true, terminalShort: true, diskFails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			var terminal, warning bytes.Buffer
			log, err := newCommandLog(home, "add", &warning, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer log.close(0)
			if test.diskFails {
				if err := log.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			wantErr := io.ErrClosedPipe
			if test.terminalShort {
				wantErr = io.ErrShortWrite
			}
			calls := 0
			output := &loggedOutput{log: log, stream: "stderr", terminal: progressSinkFunc(func(data []byte) (int, error) {
				calls++
				if test.terminalShort {
					return len(data) - 1, nil
				}
				if test.terminalFails {
					return 0, io.ErrClosedPipe
				}
				return terminal.Write(data)
			})}
			const progress = "progress: add: observed\n"
			for range 3 {
				n, err := output.WriteProgress([]byte(progress))
				if test.terminalFails && test.diskFails {
					if !errors.Is(err, wantErr) {
						t.Fatalf("all failed destinations reported success: n=%d err=%v", n, err)
					}
				} else if err != nil || n != len(progress) {
					t.Fatalf("one failed destination disabled the other: n=%d err=%v", n, err)
				}
			}
			if test.terminalFails {
				if calls != 1 {
					t.Fatalf("failed terminal progress was retried: %d calls", calls)
				}
				// Ordinary writes remain mandatory even when their bytes happen
				// to look like progress. Dispatch must not parse a text prefix.
				if _, err := io.WriteString(output, "progress: mandatory diagnostic\n"); !errors.Is(err, wantErr) || calls != 2 {
					t.Fatalf("mandatory diagnostic error was hidden: calls=%d err=%v", calls, err)
				}
			} else if terminal.String() != strings.Repeat(progress, 3) {
				t.Fatalf("disk failure lost terminal progress: %q", &terminal)
			}
			if !test.diskFails {
				if got := recordedStream(readDebugLogs(t, home), "stderr"); !strings.HasPrefix(got, strings.Repeat(progress, 3)) {
					t.Fatalf("terminal failure lost disk progress: %q", got)
				}
			} else if strings.Count(warning.String(), "warning: disk debug logging unavailable:") != 1 {
				t.Fatalf("disk failure did not warn exactly once: %q", &warning)
			}
		})
	}
}

func TestProgressDiskCopyDoesNotHideMandatoryScanWarnings(t *testing.T) {
	root := t.TempDir()
	if err := run(context.Background(), []string{"init", "--root", root}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("absent", filepath.Join(root, "broken")); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	log, err := newCommandLog(home, "add", io.Discard, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer log.close(1)
	output := &loggedOutput{terminal: failingWriter{}, log: log, stream: "stderr"}
	if err := run(context.Background(), []string{"add", "--root", root, "--allow-empty"}, io.Discard, output); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("healthy disk copy hid a mandatory scan-warning failure: %v", err)
	}
	if diagnostics := recordedStream(readDebugLogs(t, home), "stderr"); !strings.Contains(diagnostics, "broken-symlink-skipped") {
		t.Fatalf("mandatory warning was not captured on disk: %s", diagnostics)
	}
}
