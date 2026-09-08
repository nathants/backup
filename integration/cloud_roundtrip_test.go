package integration

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	libsodium "github.com/nathants/go-libsodium"
)

// Exercise the real CLI with the same single profile used by the destructive
// contract. No administrator credential or primary remote is needed to recover.
func runCloudRoundTrip(t *testing.T, config cloudContractConfig) {
	t.Helper()
	workspace := t.TempDir()
	if parent := os.Getenv("BACKUP_CONTRACT_EVIDENCE_DIR"); parent != "" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		var err error
		workspace, err = os.MkdirTemp(parent, "cloud-"+strings.ToLower(config.name)+"-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("retained private round-trip workspace: %s", workspace)
	}
	binary := filepath.Join(t.TempDir(), "backup")
	run(t, "..", "go", "build", "-o", binary, "./cmd/backup")
	source := filepath.Join(workspace, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(workspace, "metadata.git")
	run(t, "", "git", "init", "--bare", "--object-format=sha256", "--initial-branch=main", remote)
	profile := "[backup]\naws_access_key_id = " + config.credential.AccessKeyID + "\naws_secret_access_key = " + config.credential.SecretAccessKey + "\n"
	if config.credential.SessionToken != "" {
		profile += "aws_session_token = " + config.credential.SessionToken + "\n"
	}
	credentialPath := filepath.Join(workspace, "credentials")
	writeFile(t, credentialPath, []byte(profile), 0o600)
	prefix := strings.TrimPrefix(config.prefix+"/roundtrip-"+randomContractHex(t, 16), "/")
	endpoint := config.endpoint
	if endpoint == "" {
		endpoint = "-"
	}
	configPath := filepath.Join(workspace, "backup-config")
	writeFile(t, configPath, []byte(fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tcloud\t%s\ts3://%s/%s\t%s\t%s\tbackup\t-\n", remote, config.kind, config.bucket, prefix, endpoint, config.region)), 0o600)
	libsodium.Init()
	public, secret, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(workspace, "recovery.secret"), []byte(hex.EncodeToString(secret)+"\n"), 0o600)
	environment := cleanEnvironment(map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": credentialPath,
		"AWS_CONFIG_FILE":             "/dev/null", "AWS_EC2_METADATA_DISABLED": "true",
		"GIT_REMOTE_AWS_SECRETKEY": hex.EncodeToString(secret),
	})
	command := func(name string, args ...string) string {
		t.Helper()
		args = append([]string{name, "--root", source, "--config", configPath}, args...)
		output := runEnv(t, "", environment, binary, args...)
		t.Logf("%s %s:\n%s", config.name, name, output)
		return output
	}
	if output := command("init"); outputField(t, output, "publication") != "local-only" || strings.Contains(output, "commit\t") {
		t.Fatalf("initialization claimed publication: %s", output)
	}
	if refs := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "for-each-ref", "--format=%(objectname)")); refs != "" {
		t.Fatalf("initialization changed the remote: %s", refs)
	}
	writeFile(t, filepath.Join(source, ".backup", ".publickeys"), []byte(hex.EncodeToString(public)+"\n"), 0644)
	mtime := time.Unix(1_700_000_000, 123_456_789)
	for _, name := range []string{"file with spaces", "duplicate"} {
		path := filepath.Join(source, name)
		writeFile(t, path, []byte("original content\n"), 0o640)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(source, "empty"), nil, 0o600)
	if err := os.Symlink("file with spaces", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	command("add")
	first := outputField(t, command("commit"), "commit")
	genesis := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "rev-list", "--max-parents=0", first))
	if len(genesis) != 64 {
		t.Fatalf("first publication lacks a single genesis: %s", genesis)
	}
	// Rotate between cloud revisions. Restore/recovery must select both retained
	// generations, while newly encrypted packs and bundles use only the tip key.
	rotatedPublic, rotatedSecret, err := libsodium.RotateKeyChain(libsodium.KeyChains{{public}}, libsodium.KeyChains{{secret}})
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := rotatedPublic.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	secretText, err := rotatedSecret.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(workspace, "recovery.secret"), secretText, 0600)
	writeFile(t, filepath.Join(source, ".backup", ".publickeys"), publicText, 0644)
	for i, entry := range environment {
		if strings.HasPrefix(entry, "GIT_REMOTE_AWS_SECRETKEY=") {
			environment[i] = "GIT_REMOTE_AWS_SECRETKEY=" + string(secretText)
		}
	}
	writeFile(t, filepath.Join(source, "later"), []byte("second revision\n"), 0o600)
	command("add")
	latest := outputField(t, command("commit"), "commit")
	if latest == first || first == genesis {
		t.Fatal("distinct revisions were not published")
	}
	if output := command("verify"); !strings.Contains(output, "passed\t1\n") {
		t.Fatal("cloud verification did not pass")
	}
	target := filepath.Join(workspace, "restored")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	command("restore", "--target", target, `^\./`, latest)
	for _, name := range []string{"file with spaces", "duplicate"} {
		assertFile(t, filepath.Join(target, name), []byte("original content\n"), 0o640, mtime.UnixNano())
	}
	assertFile(t, filepath.Join(target, "empty"), nil, 0o600, -1)
	assertFile(t, filepath.Join(target, "later"), []byte("second revision\n"), 0o600, -1)
	one, err := os.Stat(filepath.Join(target, "file with spaces"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := os.Stat(filepath.Join(target, "duplicate"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(one, two) {
		t.Fatal("deduplicated paths share an inode")
	}
	link, err := os.Readlink(filepath.Join(target, "link"))
	if err != nil || link != "file with spaces" {
		t.Fatalf("restored symlink=%q err=%v", link, err)
	}
	selected := filepath.Join(workspace, "selected")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	command("restore", "--target", selected, `^\./file with spaces$`, first)
	assertFile(t, filepath.Join(selected, "file with spaces"), []byte("original content\n"), 0o640, mtime.UnixNano())
	entries, err := os.ReadDir(selected)
	if err != nil || len(entries) != 1 {
		t.Fatalf("selected restore entries=%d err=%v", len(entries), err)
	}
	if err := os.Rename(remote, remote+".unavailable"); err != nil {
		t.Fatal(err)
	}
	command("recover", "--mirror", "cloud", "--list")
	for _, tip := range []string{latest, genesis} {
		destination := filepath.Join(workspace, "recovered-"+tip+".git")
		args := []string{"--mirror", "cloud", "--destination", destination}
		if tip == genesis {
			args = append(args, "--tip", genesis)
		}
		if outputField(t, command("recover", args...), "recovered-tip") != tip {
			t.Fatal("recovery selected the wrong tip")
		}
		if got := strings.TrimSpace(run(t, "", "git", "--git-dir", destination, "rev-parse", "refs/backup/recovered-tip")); got != tip {
			t.Fatalf("recovered Git ref=%s", got)
		}
	}
	t.Logf("%s real CLI round-trip passed: s3://%s/%s genesis=%s latest=%s; content/mode/nanosecond-mtime/symlink/independent-inode checks and selected historical restore passed", config.name, config.bucket, prefix, genesis, latest)
}
