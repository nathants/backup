package integration

import (
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/s3server"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/nathants/go-libsodium"
)

// Creates a fresh scratch bucket and table and deletes them afterwards. Never
// enable this with credentials for a production account.
func TestAWSGitRemoteKeychains(t *testing.T) {
	if os.Getenv("BACKUP_GIT_REMOTE_CONTRACT") != "1" {
		t.Skip("requires explicit scratch Git-remote contract")
	}
	account := os.Getenv("LIBAWS_TEST_ACCOUNT")
	if account == "" {
		t.Fatal("scratch account required")
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
	path := workspace + string(os.PathListSeparator) + os.Getenv("PATH")
	scratch := createGitRemoteResources(t, account, cleanEnvironment(map[string]string{"PATH": path, "AWS_SHARED_CREDENTIALS_FILE": credentials, "AWS_CONFIG_FILE": awsConfig, "AWS_EC2_METADATA_DISABLED": "true", "ensure": "y"}))
	root := filepath.Join(workspace, "source")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	remote := "aws://" + scratch + "+" + scratch + "/backup-keys-" + randomContractHex(t, 16)
	config := filepath.Join(workspace, "backup-config")
	writeFile(t, config, []byte(fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://%s\t%s\t%s\tbackup\t%s\n", remote, testBucket, httpServer.URL, testRegion, ca)), 0600)
	libsodium.Init()
	pub, sec, err := libsodium.RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secretFile, loader := filepath.Join(workspace, "secret"), filepath.Join(workspace, "loader")
	writeFile(t, loader, []byte("#!/bin/sh\n[ \"$1\" = '"+remote+"' ] || exit 2\ncat '"+secretFile+"'\n"), 0700)
	env := cleanEnvironment(map[string]string{"PATH": path, "AWS_SHARED_CREDENTIALS_FILE": credentials, "AWS_CONFIG_FILE": awsConfig, "AWS_EC2_METADATA_DISABLED": "true", "GIT_REMOTE_AWS_SECRETKEY_CMD": loader})
	command := func(name string, args ...string) string {
		t.Helper()
		return runEnv(t, "", env, binary, append([]string{name, "--root", root, "--config", config}, args...)...)
	}
	command("init")
	latest := ""
	for generation := range 2 {
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
	for i := range 2 {
		data, err := os.ReadFile(filepath.Join(target, fmt.Sprintf("generation-%d", i)))
		if err != nil || string(data) != fmt.Sprintf("generation %d", i) {
			t.Fatalf("bad restored generation %d: %v", i, err)
		}
	}
	command("verify")
}

// createGitRemoteResources creates a fresh bucket and table of the same name
// through the helper's ensure=y setup and, after the test, permanently deletes
// both, including every object version and delete marker. The helper never
// retries an uncertain CreateBucket, so setup is retried only while the bucket,
// which it creates first, is still absent.
func createGitRemoteResources(t *testing.T, account string, env []string) string {
	t.Helper()
	name := "backup-git-test-" + randomContractHex(t, 16)
	t.Logf("scratch bucket and table: %s", name)
	t.Cleanup(func() {
		for _, arguments := range [][]string{{"s3-rm-bucket", name}, {"dynamodb-rm", name}} {
			if output, err := exec.Command("libaws", arguments...).CombinedOutput(); err != nil {
				t.Errorf("libaws %v: %v: %s", arguments, err, output)
			}
		}
	})
	loaded, err := awsconfig.LoadDefaultConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	client := s3.NewFromConfig(loaded)
	directory := t.TempDir()
	runEnv(t, directory, env, "git", "init", "-q")
	for attempt := 1; ; attempt++ {
		setup := exec.Command("git", "ls-remote", "aws://"+name+"+"+name+"/setup")
		setup.Dir, setup.Env = directory, env
		output, err := setup.CombinedOutput()
		if err == nil {
			return name
		}
		_, headErr := client.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: aws.String(name), ExpectedBucketOwner: aws.String(account)})
		if status, _ := cloudHTTPStatus(headErr); attempt == 3 || status != http.StatusNotFound {
			t.Fatalf("create scratch bucket and table through ensure=y: %v: %s", errors.Join(err, headErr), output)
		}
	}
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
	for _, missing := range []string{"LIBAWS_TEST_ACCOUNT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Run(missing, func(t *testing.T) {
			env := map[string]string{
				"LIBAWS_TEST_ACCOUNT": "123456789012", "AWS_ACCESS_KEY_ID": "synthetic",
				"AWS_SECRET_ACCESS_KEY": "synthetic",
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
