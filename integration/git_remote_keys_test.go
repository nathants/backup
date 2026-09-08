package integration

import (
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/s3server"

	"github.com/nathants/go-libsodium"
)

// Uses a dedicated externally provisioned scratch bucket/table, cleaned by the
// invoking harness. Never enable this against a production metadata namespace.
func TestAWSGitRemoteKeychains(t *testing.T) {
	if os.Getenv("BACKUP_GIT_REMOTE_CONTRACT") != "1" {
		t.Skip("requires explicit scratch Git-remote contract")
	}
	account, bucket, table := os.Getenv("GIT_REMOTE_AWS_TEST_ACCOUNT"), os.Getenv("GIT_REMOTE_AWS_TEST_BUCKET"), os.Getenv("GIT_REMOTE_AWS_TEST_TABLE")
	if account == "" || bucket == "" || table == "" {
		t.Fatal("scratch account/bucket/table required")
	}
	if strings.TrimSpace(run(t, "", "libaws", "aws-account")) != account {
		t.Fatal("wrong scratch account")
	}
	region := strings.TrimSpace(run(t, "", "libaws", "aws-region"))
	workspace := t.TempDir()
	binary := filepath.Join(workspace, "backup")
	run(t, "..", "go", "build", "-o", binary, "./cmd/backup")
	run(t, "../../git-remote-aws", "go", "build", "-o", filepath.Join(workspace, "git-remote-aws"), ".")
	server, err := s3server.Open(s3server.Config{Root: filepath.Join(workspace, "objects"), Bucket: testBucket, Region: testRegion, Credential: s3server.Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	httpServer := httptest.NewTLSServer(server)
	t.Cleanup(httpServer.Close)
	ca := filepath.Join(workspace, "ca.pem")
	writeFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0600)
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Fatal("explicit scratch credentials required")
	}
	credentials := filepath.Join(workspace, "credentials")
	profile := "[default]\naws_access_key_id = " + os.Getenv("AWS_ACCESS_KEY_ID") + "\naws_secret_access_key = " + os.Getenv("AWS_SECRET_ACCESS_KEY") + "\n"
	if token := os.Getenv("AWS_SESSION_TOKEN"); token != "" {
		profile += "aws_session_token = " + token + "\n"
	}
	profile += "[backup]\naws_access_key_id = " + accessKey + "\naws_secret_access_key = " + secretKey + "\n"
	writeFile(t, credentials, []byte(profile), 0600)
	awsConfig := filepath.Join(workspace, "aws-config")
	writeFile(t, awsConfig, []byte("[default]\nregion = "+region+"\n"), 0600)
	root := filepath.Join(workspace, "source")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	remote := "aws://" + bucket + "+" + table + "/backup-keys-" + randomContractHex(t, 16)
	config := filepath.Join(workspace, "backup-config")
	writeFile(t, config, []byte(fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://%s\t%s\t%s\tbackup\t%s\n", remote, testBucket, httpServer.URL, testRegion, ca)), 0600)
	libsodium.Init()
	pub, sec, err := libsodium.RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secretFile, loader := filepath.Join(workspace, "secret"), filepath.Join(workspace, "loader")
	writeFile(t, loader, []byte("#!/bin/sh\n[ \"$1\" = '"+remote+"' ] || exit 2\ncat '"+secretFile+"'\n"), 0700)
	env := cleanEnvironment(map[string]string{"PATH": workspace + string(os.PathListSeparator) + os.Getenv("PATH"), "AWS_SHARED_CREDENTIALS_FILE": credentials, "AWS_CONFIG_FILE": awsConfig, "AWS_EC2_METADATA_DISABLED": "true", "GIT_REMOTE_AWS_SECRETKEY_CMD": loader})
	command := func(name string, args ...string) string {
		t.Helper()
		return runEnv(t, "", env, binary, append([]string{name, "--root", root, "--config", config}, args...)...)
	}
	command("init")
	latest := ""
	for generation := 0; generation < 2; generation++ {
		ptext, err := pub.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		stext, err := sec.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, secretFile, stext, 0600)
		writeFile(t, filepath.Join(root, ".backup", ".publickeys"), ptext, 0644)
		writeFile(t, filepath.Join(root, fmt.Sprintf("generation-%d", generation)), []byte(fmt.Sprintf("generation %d", generation)), 0600)
		command("add")
		latest = outputField(t, command("commit"), "commit")
		if generation == 0 {
			pub, sec, err = libsodium.RotateKeyChain(pub, sec)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	clone := filepath.Join(workspace, "clone")
	runEnv(t, "", env, "git", "clone", remote, clone)
	if tip := strings.TrimSpace(run(t, "", "git", "-C", clone, "rev-parse", "HEAD")); tip != latest {
		t.Fatal("helper clone disagrees with backup revision")
	}
	target := filepath.Join(workspace, "restore")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	command("restore", "--target", target, `^\./generation-`, latest)
	for i := 0; i < 2; i++ {
		data, err := os.ReadFile(filepath.Join(target, fmt.Sprintf("generation-%d", i)))
		if err != nil || string(data) != fmt.Sprintf("generation %d", i) {
			t.Fatalf("bad restored generation %d: %v", i, err)
		}
	}
	command("verify")
}

func TestCloudFreeEnvironmentDisablesGitContract(t *testing.T) {
	t.Setenv("BACKUP_GIT_REMOTE_CONTRACT", "1")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", "synthetic-secret")
	command := exec.Command("./cloud-free-env.sh", "sh", "-c", `test -z "${BACKUP_GIT_REMOTE_CONTRACT:-}" && test -z "${GIT_REMOTE_AWS_SECRETKEY:-}"`)
	if err := command.Run(); err != nil {
		t.Fatal("cloud-free environment leaked Git contract/secret configuration")
	}
}

func TestGitPrimaryRunnerRequiresExplicitGuards(t *testing.T) {
	for _, missing := range []string{"LIBAWS_TEST_ACCOUNT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GIT_REMOTE_AWS_TEST_OLD_BINARY"} {
		t.Run(missing, func(t *testing.T) {
			env := map[string]string{
				"LIBAWS_TEST_ACCOUNT": "123456789012", "AWS_ACCESS_KEY_ID": "synthetic",
				"AWS_SECRET_ACCESS_KEY": "synthetic", "GIT_REMOTE_AWS_TEST_OLD_BINARY": "/absent",
			}
			env[missing] = ""
			cmd := exec.Command("bash", "./git-remote.sh")
			cmd.Env = cleanEnvironment(env)
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), missing) {
				t.Fatalf("missing guard %s did not fail before AWS access: %v: %s", missing, err, output)
			}
		})
	}
}

func TestGitPrimaryInventoryGuard(t *testing.T) {
	data, err := os.ReadFile("git-remote.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, code, ok := strings.Cut(string(data), "<<'PY'\n")
	if !ok {
		t.Fatal("missing runner inventory guard")
	}
	code, _, ok = strings.Cut(code, "\nPY\n")
	if !ok {
		t.Fatal("unterminated runner inventory guard")
	}
	for _, existing := range []string{"neither", "bucket", "table"} {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			bucket, table := `{"Buckets":[]}`, `{"TableNames":[]}`
			if existing == "bucket" {
				bucket = `{"Buckets":[{"Name":"fixture"}]}`
			}
			if existing == "table" {
				table = `{"TableNames":["fixture"]}`
			}
			writeFile(t, filepath.Join(dir, "buckets-before.json"), []byte(bucket), 0600)
			writeFile(t, filepath.Join(dir, "tables-before.json"), []byte(table), 0600)
			cmd := exec.Command("python3", "-O", "-", dir, "fixture")
			cmd.Stdin = strings.NewReader(code)
			err := cmd.Run()
			if (err == nil) != (existing == "neither") {
				t.Fatalf("inventory guard for %s: %v", existing, err)
			}
		})
	}
}
