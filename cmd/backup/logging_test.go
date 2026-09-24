package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run the real entry point, including final error reporting and process status.
func TestLoggingCLIProcess(_ *testing.T) {
	if os.Getenv("BACKUP_LOGGING_TEST_PROCESS") != "1" {
		return
	}
	for index, argument := range os.Args {
		if argument == "--" {
			os.Args = append([]string{"backup"}, os.Args[index+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func loggingCLI(t *testing.T, home string, arguments ...string) (string, string, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, append([]string{"-test.run=^TestLoggingCLIProcess$", "--"}, arguments...)...)
	command.Env = append(os.Environ(), "BACKUP_LOGGING_TEST_PROCESS=1", "HOME="+home)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	return stdout.String(), stderr.String(), err
}

type recordedOutput struct {
	Time    time.Time `json:"time"`
	Run     string    `json:"run"`
	Command string    `json:"command"`
	Stream  string    `json:"stream"`
	Message string    `json:"message"`
}

func readDebugLogs(t *testing.T, home string) []recordedOutput {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(home, ".backup-logs", "backup-*.jsonl"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no debug logs: %v", err)
	}
	var records []recordedOutput
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var record recordedOutput
			err := decoder.Decode(&record)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil || record.Time.IsZero() {
				t.Fatalf("invalid debug log record: %+v %v", record, err)
			}
			records = append(records, record)
		}
	}
	return records
}

func recordedStream(records []recordedOutput, stream string) string {
	var result strings.Builder
	for _, record := range records {
		if record.Stream == stream {
			result.WriteString(record.Message)
		}
	}
	return result.String()
}

func TestCLILoggingMainEntryPoint(t *testing.T) {
	for _, arguments := range [][]string{{"--help"}, {"unknown\ncommand"}} {
		t.Run(arguments[0], func(t *testing.T) {
			home := t.TempDir()
			stdout, stderr, err := loggingCLI(t, home, arguments...)
			if arguments[0] == "--help" {
				if err != nil || !strings.Contains(stdout, "usage: backup COMMAND") || stderr != "" {
					t.Fatalf("help: stdout=%q stderr=%q err=%v", stdout, stderr, err)
				}
			} else if err == nil || !strings.Contains(stderr, "backup: unknown command") || strings.Contains(stderr, "unknown\ncommand") {
				t.Fatalf("error reporting: stdout=%q stderr=%q err=%v", stdout, stderr, err)
			}
			records := readDebugLogs(t, home)
			if recordedStream(records, "stdout") != stdout || recordedStream(records, "stderr") != stderr {
				t.Fatalf("disk output differs from terminal: %+v", records)
			}
		})
	}
}

func TestCLILoggingEveryCommandAndPrivateFiles(t *testing.T) {
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", "environment-secret-must-not-be-logged")
	t.Setenv("BACKUP_SERVER_SECRET_KEY", "server-secret-must-not-be-logged")
	for _, command := range []string{"help", "init", "add", "replan", "diff", "commit", "reset", "find", "restore", "verify", "sync", "repair", "repair data", "repair metadata", "recover", "server", "mirror-init"} {
		t.Run(command, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			arguments := append(strings.Fields(command), "--help")
			if command == "restore" {
				arguments = []string{"restore", "--root", "argument-not-to-be-dumped", "--help"}
			}
			var stdout, stderr bytes.Buffer
			if status := execute(context.Background(), arguments, &stdout, &stderr); status != 0 || stderr.Len() != 0 {
				t.Fatalf("help: status=%d stderr=%s", status, &stderr)
			}
			records := readDebugLogs(t, home)
			if recordedStream(records, "stdout") != stdout.String() || !strings.HasPrefix(stdout.String(), "usage: backup ") {
				t.Fatalf("missing command output: %+v", records)
			}
			for _, record := range records {
				if record.Command != command || strings.Contains(record.Message, "must-not-be-logged") || strings.Contains(record.Message, "argument-not-to-be-dumped") {
					t.Fatalf("wrong command identity or unnecessary input dump: %+v", record)
				}
			}
			if recordedStream(records, "command") != "startexit 0" {
				t.Fatalf("missing command lifecycle: %+v", records)
			}
			directory := filepath.Join(home, ".backup-logs")
			if info, err := os.Stat(directory); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("log directory is not private: %v %v", info, err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
					t.Fatalf("log file is not private: %v %v", info, err)
				}
			}
		})
	}
}

func writeAgedLog(t *testing.T, directory, name string, modified time.Time) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("retention fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDebugLogRetentionAndConfinement(t *testing.T) {
	home := t.TempDir()
	directory, err := openDebugLogDirectory(home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-14 * 24 * time.Hour)
	name := func(index int) string { return fmt.Sprintf("backup-2026-09-10-%032x.jsonl", index) }
	// Cross the bounded directory-read batch size as well as the age boundary.
	var expired []string
	for index := range 300 {
		expired = append(expired, writeAgedLog(t, directory.Name(), name(index), cutoff.Add(-time.Second)))
	}
	kept := []string{
		writeAgedLog(t, directory.Name(), name(301), cutoff),
		writeAgedLog(t, directory.Name(), name(302), cutoff.Add(time.Second)),
		writeAgedLog(t, directory.Name(), name(303), now.Add(time.Hour)),
		writeAgedLog(t, directory.Name(), "another-program.log", cutoff.Add(-time.Hour)),
		writeAgedLog(t, directory.Name(), "backup-2026-99-99-"+strings.Repeat("0", 32)+".jsonl", cutoff.Add(-time.Hour)),
	}
	outside := writeAgedLog(t, home, "important", cutoff.Add(-time.Hour))
	symlink := filepath.Join(directory.Name(), name(304))
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory.Name(), name(305))
	if err := os.Link(outside, hardlink); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(directory.Name(), name(306))
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	child := writeAgedLog(t, nested, "important", cutoff.Add(-time.Hour))
	fifo := filepath.Join(directory.Name(), name(307))
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, outside, symlink, hardlink, child, fifo)
	if err := pruneDebugLogs(directory, now); err != nil {
		t.Fatal(err)
	}
	for _, path := range expired {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expired log retained: %s %v", path, err)
		}
	}
	for _, path := range kept {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("retention removed a recent or unrelated entry: %s %v", path, err)
		}
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "retention fixture\n" {
		t.Fatalf("retention damaged an external file: %q %v", data, err)
	}
}

func TestCLILoggingPrunesAtStartup(t *testing.T) {
	home := t.TempDir()
	directory, err := openDebugLogDirectory(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	expired := writeAgedLog(t, directory.Name(), "backup-2026-01-01-"+strings.Repeat("0", 32)+".jsonl", time.Now().Add(-15*24*time.Hour))
	_, stderr, err := loggingCLI(t, home, "--help")
	if err != nil || stderr != "" {
		t.Fatalf("startup cleanup: %q %v", stderr, err)
	}
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("command did not prune old logs: %v", err)
	}
}

func TestDebugLogDailyRotation(t *testing.T) {
	home := t.TempDir()
	now := time.Now().UTC().Truncate(24 * time.Hour).Add(23*time.Hour + 59*time.Minute)
	var warning, terminal bytes.Buffer
	log, err := newCommandLog(home, "server", &warning, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	output := &loggedOutput{terminal: &terminal, log: log, stream: "stderr"}
	if _, err := io.WriteString(output, "before midnight\n"); err != nil {
		t.Fatal(err)
	}
	first := log.file.Name()
	firstPath := filepath.Join(log.directory.Name(), first)
	now = now.Add(2 * time.Minute)
	if _, err := io.WriteString(output, "after midnight\n"); err != nil {
		t.Fatal(err)
	}
	second := log.file.Name()
	if first == second {
		t.Fatal("a long-running server did not rotate its log")
	}
	if data, err := os.ReadFile(firstPath); err != nil || !bytes.Contains(data, []byte("before midnight")) || bytes.Contains(data, []byte("after midnight")) {
		t.Fatalf("rotation mixed days: %q %v", data, err)
	}
	if err := os.Chtimes(firstPath, now.Add(-15*24*time.Hour), now.Add(-15*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	if _, err := io.WriteString(output, "another day\n"); err != nil {
		t.Fatal(err)
	}
	log.close(0)
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rotation did not expire old logs: %v", err)
	}
	if warning.Len() != 0 || terminal.String() != "before midnight\nafter midnight\nanother day\n" {
		t.Fatalf("rotation changed terminal output: %q %q", &terminal, &warning)
	}
	if got := recordedStream(readDebugLogs(t, home), "stderr"); got != "after midnight\nanother day\n" {
		t.Fatalf("rotation lost retained output: %q", got)
	}
}

func TestCLILoggingSetupFailureIsOnlyAWarning(t *testing.T) {
	for _, kind := range []string{"unset-home", "relative-home", "directory-symlink", "directory-writable", "directory-public", "not-directory"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			directory := filepath.Join(home, ".backup-logs")
			outside := t.TempDir()
			switch kind {
			case "unset-home":
				home = ""
			case "relative-home":
				home = "relative-home-must-not-be-created"
			case "directory-symlink":
				if err := os.Symlink(outside, directory); err != nil {
					t.Fatal(err)
				}
			case "not-directory":
				if err := os.WriteFile(directory, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0o755)
				if kind == "directory-writable" {
					mode = 0o722
				}
				if err := os.Chmod(directory, mode); err != nil {
					t.Fatal(err)
				}
			}
			stdout, stderr, err := loggingCLI(t, home, "--help")
			if err != nil || !strings.HasPrefix(stdout, "usage: backup COMMAND") || strings.Count(stderr, "warning: disk debug logging unavailable:") != 1 {
				t.Fatalf("logging failure changed help: stdout=%q stderr=%q err=%v", stdout, stderr, err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("logging followed a directory symlink: %v %v", entries, err)
			}
		})
	}
}

func TestDebugLogFailurePreservesTerminalWritesAndErrors(t *testing.T) {
	home := t.TempDir()
	var terminal, warnings bytes.Buffer
	log, err := newCommandLog(home, "add", &warnings, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.file.Close(); err != nil {
		t.Fatal(err)
	}
	output := &loggedOutput{terminal: &terminal, log: log, stream: "stdout"}
	for range 3 {
		if n, err := io.WriteString(output, "result\n"); err != nil || n != len("result\n") {
			t.Fatalf("disk error propagated to command: n=%d err=%v", n, err)
		}
	}
	output.terminal = failingWriter{}
	if _, err := io.WriteString(output, "mandatory result\n"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("disk failure hid terminal failure: %v", err)
	}
	log.close(0)
	if strings.Count(warnings.String(), "warning: disk debug logging unavailable:") != 1 || terminal.String() != strings.Repeat("result\n", 3) {
		t.Fatalf("repeated warnings or lost terminal output: %q %q", &warnings, &terminal)
	}
}

func TestCLILoggingKeepsMandatoryOutputFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var stderr bytes.Buffer
	if status := execute(context.Background(), []string{"--help"}, failingWriter{}, &stderr); status != 1 || !strings.Contains(stderr.String(), io.ErrClosedPipe.Error()) {
		t.Fatalf("mandatory output failure lost: status=%d stderr=%s", status, &stderr)
	}
	records := readDebugLogs(t, home)
	if recordedStream(records, "stdout") != usageText || recordedStream(records, "stderr") != stderr.String() || recordedStream(records, "command") != "startexit 1" {
		t.Fatalf("missing failed command diagnostics: %+v", records)
	}
}

func TestDebugLogConcurrentWritesAndBoundedRecords(t *testing.T) {
	home := t.TempDir()
	var terminal, warnings bytes.Buffer
	log, err := newCommandLog(home, "server", &warnings, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	output := &loggedOutput{terminal: &terminal, log: log, stream: "stderr"}
	text := strings.Repeat("界", 20000) + "\n\x1b[31m\tcontrol\n"
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if n, err := io.WriteString(output, text); err != nil || n != len(text) {
				t.Errorf("write: %d %v", n, err)
			}
		})
	}
	workers.Wait()
	log.close(0)
	records := readDebugLogs(t, home)
	if warnings.Len() != 0 || terminal.String() != strings.Repeat(text, 8) || recordedStream(records, "stderr") != terminal.String() {
		t.Fatal("concurrent or chunked logging damaged output")
	}
	for _, record := range records {
		if len(record.Message) > 16<<10 {
			t.Fatalf("unbounded record: %d bytes", len(record.Message))
		}
	}
}

func TestDebugLogConcurrentCommands(t *testing.T) {
	home := t.TempDir()
	directory, err := openDebugLogDirectory(home)
	if err != nil {
		t.Fatal(err)
	}
	expired := writeAgedLog(t, directory.Name(), "backup-2026-01-01-"+strings.Repeat("0", 32)+".jsonl", time.Now().Add(-15*24*time.Hour))
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			var stdout, stderr bytes.Buffer
			if status := execute(context.Background(), []string{"--help"}, &stdout, &stderr); status != 0 || stdout.String() != usageText || stderr.Len() != 0 {
				t.Errorf("concurrent invocation failed: %d %s", status, &stderr)
			}
		})
	}
	workers.Wait()
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("concurrent pruning failed: %v", err)
	}
	records := readDebugLogs(t, home)
	lifecycles := make(map[string]string)
	for _, record := range records {
		if record.Stream == "command" {
			lifecycles[record.Run] += record.Message
		}
	}
	if recordedStream(records, "stdout") != strings.Repeat(usageText, 12) || len(lifecycles) != 12 {
		t.Fatal("concurrent commands lost each other's logs")
	}
	for run, lifecycle := range lifecycles {
		if run == "" || lifecycle != "startexit 0" {
			t.Fatalf("cannot correlate concurrent command start/exit: %q %q", run, lifecycle)
		}
	}
}

type panicOutput struct{}

func (panicOutput) Write([]byte) (int, error) { panic("injected output panic") }

func TestCLILoggingDoesNotClaimSuccessDuringPanic(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	var failure any
	func() {
		defer func() { failure = recover() }()
		execute(context.Background(), []string{"--help"}, panicOutput{}, io.Discard)
	}()
	if failure == nil {
		t.Fatal("entry point swallowed a panic")
	}
	if got := recordedStream(readDebugLogs(t, home), "command"); got != "startaborted" {
		t.Fatalf("unwinding command recorded an exit status it did not return: %q", got)
	}
}
