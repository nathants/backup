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

func TestRestoreHelpStatesExclusiveDestinationRequirement(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"restore", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "exclusive control of the destination tree") || !strings.Contains(stdout.String(), "concurrent destination writers are unsupported") {
		t.Fatalf("restore help omits destination safety boundary: %q", stdout.String())
	}
}

func TestSubcommandHelpDescribesCommand(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent-root")
	t.Setenv("BACKUP_ROOT", root)
	t.Setenv("BACKUP_CONFIG", filepath.Join(root, "absent-config"))
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", "invalid-secret-must-not-be-loaded")
	for _, test := range []struct {
		command  string
		synopsis string
		want     []string
	}{
		{"init", "[OPTIONS]", []string{"local preparation", "no network publication", "-root string", "-config string"}},
		{"add", "[OPTIONS]", []string{"-allow-empty", "-spool-directory string", "-space-reserve-bytes uint", "provisional"}},
		{"replan", "[OPTIONS]", []string{"directory traversal", "provisional", "without fetching or uploading", "Refuses commit progress"}},
		{"diff", "[OPTIONS]", []string{"-root string", "provisional"}},
		{"commit", "[OPTIONS]", []string{"-root string", "resume", "one individual mirror"}},
		{"reset", "[OPTIONS]", []string{"-root string", "unpublished", "ambiguous"}},
		{"find", "[OPTIONS] REGEX [REVISION]", []string{"-root string", "REVISION defaults to HEAD"}},
		{"restore", "[OPTIONS] --target DIRECTORY REGEX [REVISION]", []string{"-target string", "-overwrite", "-catalog-revision string", "-dry-run", "REVISION defaults to HEAD", "exclusive control of the destination tree", "memory/swap", "TMPDIR"}},
		{"verify", "[OPTIONS] [REVISION]", []string{"-minimum-mirrors int", "(default 1)", "REVISION defaults to HEAD"}},
		{"sync", "[OPTIONS] --source MIRROR --destination MIRROR", []string{"-source string", "-destination string", "-revision string", "never overwrites or deletes"}},
		{"repair", "{data|metadata} [OPTIONS]", []string{"backup repair data --help", "backup repair metadata --help", "immutable"}},
		{"repair data", "[OPTIONS] --source MIRROR PACK_HASH PART_NUMBER", []string{"-source string", "zero-based", "128 lowercase hex"}},
		{"repair metadata", "[OPTIONS] --destination MIRROR", []string{"-destination string", "-revision string", "recipient secret"}},
		{"recover", "[OPTIONS] --mirror MIRROR {--list | --destination DIRECTORY}", []string{"-mirror string", "-tip string", "-destination string", "-list", "--list also decrypts and imports", "memory/swap", "TMPDIR"}},
		{"server", "[OPTIONS] --data-root DIRECTORY --bucket BUCKET --tls-cert FILE --tls-key FILE", []string{"-data-root string", "-bucket string", "-tls-cert string", "-tls-key string", "-listen string", "(default \":8443\")", "-region string", "(default \"us-east-1\")", "BACKUP_SERVER_ACCESS_KEY", "BACKUP_SERVER_SECRET_KEY"}},
	} {
		for _, helpFlag := range []string{"-h", "--help"} {
			t.Run(test.command+"/"+helpFlag, func(t *testing.T) {
				arguments := append(strings.Fields(test.command), helpFlag)
				var stdout, stderr bytes.Buffer
				if err := run(context.Background(), arguments, &stdout, &stderr); err != nil {
					t.Fatalf("help accessed runtime state or failed: %v", err)
				}
				help := stdout.String()
				if !strings.HasPrefix(help, "usage: backup "+test.command+" "+test.synopsis+"\n") || stderr.Len() != 0 {
					t.Fatalf("wrong command synopsis or output stream: stdout=%q stderr=%q", help, stderr.String())
				}
				for _, want := range test.want {
					if !strings.Contains(help, want) {
						t.Errorf("help lacks %q: %s", want, help)
					}
				}
				if strings.Contains(help, "usage: backup COMMAND") || strings.Contains(help, "invalid-secret-must-not-be-loaded") {
					t.Fatalf("help substituted generic usage or disclosed a secret source: %q", help)
				}
				if err := run(context.Background(), arguments, failingWriter{}, &stderr); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("help output error was hidden: %v", err)
				}
				if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("help created its source root: %v", err)
				}
			})
		}
	}
}

func TestInitStartsWithEmptyRecipients(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := runInit(context.Background(), []string{"--root", root}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile(filepath.Join(root, ".backup", ".publickeys"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("initial recipients: %v", err)
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
		{[]string{"init", "extra"}, "accepts no positional"},
		{[]string{"init", "--recovery-public-key", "ABC"}, "flag provided but not defined"},
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
	if err := printRecoverResult(&output, backupapp.RecoverResult{
		RecoveredTip: strings.Repeat("b", 64),
		Destination:  "/restore\ninjected\tpath",
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "/restore\ninjected\tpath") || !strings.Contains(output.String(), "destination\t/restore\\x0ainjected\\x09path\n") {
		t.Fatalf("recover output contains unescaped destination: %q", output.String())
	}
}

func TestSnapshotResult(t *testing.T) {
	var output bytes.Buffer
	if err := printSnapshotResult(&output, backupapp.SnapshotResult{CommitID: strings.Repeat("a", 64), CompleteMirrors: []string{"a"}, LaggingMirrors: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"commit\t" + strings.Repeat("a", 64), "complete-mirror\ta", "lagging-mirror\tb"} {
		if !strings.Contains(output.String(), want+"\n") {
			t.Fatalf("snapshot output %q lacks %q", output.String(), want)
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

func TestServerRequiresSingleCredentialEnvironment(t *testing.T) {
	for _, name := range []string{"BACKUP_SERVER_ACCESS_KEY", "BACKUP_SERVER_SECRET_KEY", "BACKUP_SERVER_SESSION_TOKEN"} {
		t.Setenv(name, "")
	}
	// Old names must not become a fallback credential source.
	t.Setenv("BACKUP_SERVER_WRITER_ACCESS_KEY", "old-writer")
	t.Setenv("BACKUP_SERVER_WRITER_SECRET_KEY", "old-secret")
	t.Setenv("BACKUP_SERVER_READER_ACCESS_KEY", "old-reader")
	t.Setenv("BACKUP_SERVER_READER_SECRET_KEY", "old-reader-secret")
	args := []string{"server", "--data-root", filepath.Join(t.TempDir(), "data"), "--bucket", "backup-test", "--tls-cert", "/nonexistent-backup-test.crt", "--tls-key", "/nonexistent-backup-test.key"}
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "BACKUP_SERVER_ACCESS_KEY and BACKUP_SERVER_SECRET_KEY are required") {
		t.Fatalf("legacy server credential environment was accepted: %v", err)
	}
	t.Setenv("BACKUP_SERVER_ACCESS_KEY", "backup-client")
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "BACKUP_SERVER_ACCESS_KEY and BACKUP_SERVER_SECRET_KEY are required") {
		t.Fatalf("incomplete credential accepted: %v", err)
	}
	t.Setenv("BACKUP_SERVER_SECRET_KEY", "backup-secret")
	err = run(context.Background(), args, &stdout, &stderr)
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "read TLS certificate") {
		t.Fatalf("single credential did not advance to TLS validation: %v", err)
	}
}

func TestHelpUsesEscapedEnvironmentDefaultsNotParsedValues(t *testing.T) {
	root := "/source with spaces\nterminal-control"
	config := "/local/config"
	spool := "/local/spool"
	t.Setenv("BACKUP_ROOT", root)
	t.Setenv("BACKUP_CONFIG", config)
	t.Setenv("BACKUP_SPOOL_DIRECTORY", spool)
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"restore", "--root", "/not-the-default", "--help"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`(default "/source with spaces\nterminal-control")`, `(default "/local/config")`, `(default "/local/spool")`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help lacks escaped configured default %q: %s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), root) || strings.Contains(stdout.String(), "/not-the-default") || stderr.Len() != 0 {
		t.Fatalf("help emitted raw controls or a parsed value as a default: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestHelpDoesNotHideFlagErrors(t *testing.T) {
	for _, arguments := range [][]string{
		{"restore", "--unknown", "--help"},
		{"verify", "--minimum-mirrors=bad", "--help"},
		{"restore", "--target"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(context.Background(), arguments, &stdout, &stderr); err == nil {
			t.Fatalf("help hid a flag error: %v", arguments)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("flag error printed help instead of returning a concise error: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}
