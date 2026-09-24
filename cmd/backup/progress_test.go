package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	if recordedStream(records, "stdout") != string(output) || !strings.Contains(recordedStream(records, "stderr"), "progress: add:") {
		t.Fatalf("closed progress pipe lost disk diagnostics: %+v", records)
	}
}
