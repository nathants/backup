package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	backupapp "backup/internal/backup"
	"backup/internal/format"
)

func TestHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "usage: backup COMMAND") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestSubcommandHelpSucceeds(t *testing.T) {
	for _, command := range []string{"init", "add", "diff", "commit", "reset", "find", "restore", "verify", "sync", "repair", "recover", "server"} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), []string{command, "--help"}, &stdout, &stderr); err != nil {
			t.Fatalf("%s --help: %v", command, err)
		}
		if !strings.Contains(stdout.String(), "usage: backup COMMAND") || stderr.Len() != 0 {
			t.Fatalf("%s stdout=%q stderr=%q", command, stdout.String(), stderr.String())
		}
	}
}

func TestInitPublicKeyFileIsBoundedBeforeParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publickeys")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(format.MaximumPublicKeysBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = runInit(context.Background(), []string{"--recovery-public-key", strings.Repeat("a", 64), "--public-keys", path}, &stdout, &stderr)
	if err == nil {
		t.Fatal("oversized public-key list was accepted")
	}
}

func TestTLSPrivateKeyMustBeRegularNoFollowAndPrivate(t *testing.T) {
	directory := t.TempDir()
	key := filepath.Join(directory, "server.key")
	if err := os.WriteFile(key, []byte("not a real key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(key, true); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readTLSFile(key, true)
	if err != nil || string(data) != "not a real key" {
		t.Fatalf("private key read failed: data=%q err=%v", data, err)
	}
	link := filepath.Join(directory, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTLSFile(link, true); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
}

func TestUnknownCommandAndMissingArgumentsAreErrors(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		contains  string
	}{
		{[]string{"unknown"}, "unknown command"},
		{[]string{"init"}, "requires --recovery-public-key"},
		{[]string{"init", "--recovery-public-key", "ABC"}, "lowercase hexadecimal"},
		{[]string{"add", "extra"}, "accepts no positional"},
		{[]string{"diff", "extra"}, "accepts no positional"},
		{[]string{"commit", "extra"}, "accepts no positional"},
		{[]string{"reset", "extra"}, "accepts no positional"},
		{[]string{"find"}, "requires REGEX"},
		{[]string{"find", "a", "b", "c"}, "requires REGEX"},
		{[]string{"restore"}, "requires REGEX"},
		{[]string{"verify", "a", "b"}, "accepts optional"},
		{[]string{"sync", "extra"}, "accepts no positional"},
		{[]string{"repair"}, "requires data or metadata"},
		{[]string{"repair", "unknown"}, "unknown repair subcommand"},
		{[]string{"repair", "data", "--source", "a", strings.Repeat("0", 128), "01"}, "canonical unsigned decimal"},
		{[]string{"repair", "metadata"}, "requires --destination"},
		{[]string{"recover", "extra"}, "accepts no positional"},
		{[]string{"server"}, "server requires"},
	} {
		var stdout, stderr bytes.Buffer
		err := run(context.Background(), test.arguments, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("arguments %v: err=%v, want containing %q", test.arguments, err, test.contains)
		}
	}
}

func TestRecoverResultEscapesDestination(t *testing.T) {
	var output bytes.Buffer
	printRecoverResult(&output, backupapp.RecoverResult{
		RecoveredTip: strings.Repeat("b", 64),
		Destination:  "/restore\ninjected\tpath",
	})
	if strings.Contains(output.String(), "/restore\ninjected\tpath") || !strings.Contains(output.String(), "destination\t/restore\\x0ainjected\\x09path\n") {
		t.Fatalf("recover output contains unescaped destination: %q", output.String())
	}
}

func TestSnapshotResultAndPublicKeyEncoding(t *testing.T) {
	var output bytes.Buffer
	printSnapshotResult(&output, backupapp.SnapshotResult{CommitID: strings.Repeat("a", 64), CompleteMirrors: []string{"a"}, LaggingMirrors: []string{"b"}})
	for _, want := range []string{"commit\t" + strings.Repeat("a", 64), "complete-mirror\ta", "lagging-mirror\tb"} {
		if !strings.Contains(output.String(), want+"\n") {
			t.Fatalf("snapshot output %q lacks %q", output.String(), want)
		}
	}
	key := strings.Repeat("a", 64)
	decoded, err := decodePublicKey(key)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode valid public key: len=%d err=%v", len(decoded), err)
	}
	for _, invalid := range []string{strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		if _, err := decodePublicKey(invalid); err == nil {
			t.Fatalf("invalid public key %q accepted", invalid)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestMandatoryResultOutputErrorsAreReturned(t *testing.T) {
	if err := printSnapshotResult(failingWriter{}, backupapp.SnapshotResult{CommitID: strings.Repeat("a", 64)}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("snapshot output error=%v", err)
	}
	if err := printRecoverResult(failingWriter{}, backupapp.RecoverResult{RecoveredTip: strings.Repeat("b", 64), Destination: "/tmp/recovered"}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("recover output error=%v", err)
	}
}

func TestTerminalErrorsEscapeControls(t *testing.T) {
	got := escapeTerminal("bad\npath\x00")
	if strings.ContainsAny(got, "\n\x00") || got != `bad\x0apath\x00` {
		t.Fatalf("escaped=%q", got)
	}
}
