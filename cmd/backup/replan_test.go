package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplanCLI(t *testing.T) {
	root := t.TempDir()
	invoke := func(command string) (string, error) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		err := run(context.Background(), []string{command, "--root", root}, &stdout, &stderr)
		return stdout.String(), err
	}
	write := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := invoke("init"); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("replan"); err == nil {
		t.Fatal("replan without add succeeded")
	}
	write("keep", "old", 0600)
	write("omit", "omit", 0600)
	if _, err := invoke("add"); err != nil {
		t.Fatal(err)
	}
	write("keep", "modified", 0600)
	write("new", "new", 0600)
	write(".backup/ignore", "omit\n", 0644)
	output, err := invoke("replan")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"entries\t2\n", "reused-files\t1\n", "hashed-files\t1\n", "observations\tprovisional\n"} {
		if !strings.Contains(output, want) {
			t.Fatalf("summary missing %q: %s", want, output)
		}
	}
	output, err = invoke("diff")
	if err != nil || strings.Contains(output, "./omit\t") || !strings.Contains(output, "./new\t") {
		t.Fatalf("diff does not reflect selection: %s %v", output, err)
	}
	write(".backup/ignore", "", 0644)
	output, err = invoke("replan")
	if err != nil || !strings.Contains(output, "reused-files\t3\n") || !strings.Contains(output, "hashed-files\t0\n") {
		t.Fatalf("undo ignore: %s %v", output, err)
	}
	if _, err := invoke("reset"); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("replan"); err == nil {
		t.Fatal("reset retained a usable replan")
	}
}
