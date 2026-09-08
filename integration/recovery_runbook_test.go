package integration

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backup/internal/s3server"
	libsodium "github.com/nathants/go-libsodium"
)

func TestRecoveryRestoreRunbook(t *testing.T) {
	workspace := t.TempDir()
	binary := filepath.Join(workspace, "backup")
	run(t, "..", "go", "build", "-o", binary, "./cmd/backup")
	server, err := s3server.Open(s3server.Config{
		Root: filepath.Join(workspace, "objects"), Bucket: testBucket, Region: testRegion,
		Credential: s3server.Credential{AccessKey: accessKey, SecretKey: secretKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	var puts atomic.Int64
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPut {
			puts.Add(1)
		}
		server.ServeHTTP(writer, request)
	}))
	t.Cleanup(httpServer.Close)
	ca := filepath.Join(workspace, "ca.pem")
	writeFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}), 0o600)
	credentials := filepath.Join(workspace, "credentials")
	writeFile(t, credentials, []byte("[backup]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"\n"), 0o600)
	source := filepath.Join(workspace, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(workspace, "primary.git")
	run(t, "", "git", "init", "--bare", "--object-format=sha256", "--initial-branch=main", remote)
	config := filepath.Join(workspace, "trusted-config")
	writeFile(t, config, []byte(fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://%s\t%s\t%s\tbackup\t%s\n", remote, testBucket, httpServer.URL, testRegion, ca)), 0o600)
	libsodium.Init()
	public, secret, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	environment := cleanEnvironment(map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": credentials, "AWS_CONFIG_FILE": "/dev/null",
		"AWS_EC2_METADATA_DISABLED": "true", "BACKUP_SECRET_KEY": hex.EncodeToString(secret),
	})
	command := func(name string, args ...string) string {
		t.Helper()
		return runEnv(t, "", environment, binary, append([]string{name, "--root", source, "--config", config}, args...)...)
	}
	command("init", "--recovery-public-key", hex.EncodeToString(public))
	mtime := time.Unix(1_700_000_000, 123_456_789)
	for _, name := range []string{"file with spaces", "duplicate"} {
		path := filepath.Join(source, name)
		writeFile(t, path, []byte("original\n"), 0o640)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("file with spaces", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	command("add")
	first := outputField(t, command("commit"), "commit")
	writeFile(t, filepath.Join(source, "later"), []byte("second revision\n"), 0o600)
	command("add")
	latest := outputField(t, command("commit"), "commit")
	command("verify")
	priorPuts := puts.Load()
	if priorPuts == 0 {
		t.Fatal("positive control did not observe uploads")
	}
	originalConfig, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(remote, remote+".unavailable"); err != nil {
		t.Fatal(err)
	}
	failure := runEnvFailure(t, "", environment, binary, "verify", "--root", source, "--config", config)
	if !strings.Contains(failure, "fetch") {
		t.Fatalf("outage did not reach primary fetch: %s", failure)
	}
	// Preserve, but stop using, every original source file and the old checkout.
	if err := os.Rename(source, source+".unavailable"); err != nil {
		t.Fatal(err)
	}
	for _, tip := range []string{latest, first} {
		t.Run(tip, func(t *testing.T) {
			recovered := filepath.Join(workspace, tip+".git")
			if got := outputField(t, command("recover", "--mirror", "local", "--tip", tip, "--destination", recovered), "recovered-tip"); got != tip {
				t.Fatalf("recovered wrong tip: %s", got)
			}
			root := filepath.Join(workspace, "rescue-"+tip)
			env := append(append([]string(nil), environment...),
				"BACKUP_BIN="+binary, "RECOVERED="+recovered, "TIP="+tip,
				"BRANCH=main", "RESCUE_ROOT="+root, "TRUSTED_CONFIG="+config,
				"GIT_DIR="+filepath.Join(workspace, "wrong-git-dir"), "GIT_WORK_TREE="+source)
			badEnv := append(append([]string(nil), env...), "TIP="+strings.Repeat("0", 64))
			failure := runEnvFailure(t, "", badEnv, "bash", "--noprofile", "--norc", "-c", recoveryRestoreRunbook(t))
			if !strings.Contains(failure, "recovered-tip does not match TIP") {
				t.Fatalf("wrong anchor failed at the wrong boundary: %s", failure)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("wrong anchor created rescue root: %v", err)
			}
			if heads := run(t, "", "git", "-C", recovered, "for-each-ref", "refs/heads/"); heads != "" {
				t.Fatalf("wrong anchor created a branch: %s", heads)
			}
			output := runRecoveryRestoreRunbook(t, env)
			if outputField(t, output, "snapshot-commit") != tip {
				t.Fatalf("restore selected wrong revision: %s", output)
			}
			target := filepath.Join(root, "restored")
			for _, name := range []string{"file with spaces", "duplicate"} {
				assertFile(t, filepath.Join(target, name), []byte("original\n"), 0o640, mtime.UnixNano())
			}
			link, err := os.Readlink(filepath.Join(target, "link"))
			if err != nil || link != "file with spaces" {
				t.Fatalf("restored link=%q, %v", link, err)
			}
			one, err := os.Stat(filepath.Join(target, "file with spaces"))
			if err != nil {
				t.Fatal(err)
			}
			two, err := os.Stat(filepath.Join(target, "duplicate"))
			if err != nil || os.SameFile(one, two) {
				t.Fatalf("duplicates were not independent: %v", err)
			}
			if tip == latest {
				assertFile(t, filepath.Join(target, "later"), []byte("second revision\n"), 0o600, -1)
				selected := filepath.Join(root, "selected")
				if err := os.Mkdir(selected, 0o700); err != nil {
					t.Fatal(err)
				}
				output := runEnv(t, "", environment, binary, "restore", "--root", root, "--target", selected, `^\./file with spaces$`, first)
				if outputField(t, output, "snapshot-commit") != first {
					t.Fatalf("selected restore used the wrong historical commit: %s", output)
				}
				assertFile(t, filepath.Join(selected, "file with spaces"), []byte("original\n"), 0o640, mtime.UnixNano())
				if entries, err := os.ReadDir(selected); err != nil || len(entries) != 1 {
					t.Fatalf("selected historical restore has unexpected entries: %v, %v", entries, err)
				}
			} else if _, err := os.Lstat(filepath.Join(target, "later")); !os.IsNotExist(err) {
				t.Fatalf("anchored restore included a later file: %v", err)
			}
			for _, unavailable := range []string{source, remote} {
				if _, err := os.Lstat(unavailable); !os.IsNotExist(err) {
					t.Fatalf("original path became available: %s: %v", unavailable, err)
				}
			}
		})
	}
	t.Run("git-status-failure", func(t *testing.T) {
		recovered := filepath.Join(workspace, "status-failure.git")
		command("recover", "--mirror", "local", "--tip", latest, "--destination", recovered)
		git, err := exec.LookPath("git")
		if err != nil {
			t.Fatal(err)
		}
		wrapper := filepath.Join(workspace, "bin")
		if err := os.Mkdir(wrapper, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(git, filepath.Join(wrapper, "real-git")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(wrapper, "git"), []byte(`#!/bin/sh
for arg do
  if [ "$arg" = status ]; then
    echo 'injected git status failure' >&2
    exit 1
  fi
done
exec "$(dirname "$0")/real-git" "$@"
`), 0o700)
		root := filepath.Join(workspace, "status-failure-rescue")
		env := append(append([]string(nil), environment...),
			"PATH="+wrapper+":"+os.Getenv("PATH"), "BACKUP_BIN="+binary,
			"RECOVERED="+recovered, "TIP="+latest, "BRANCH=main",
			"RESCUE_ROOT="+root, "TRUSTED_CONFIG="+config)
		output := runEnvFailure(t, "", env, "bash", "--noprofile", "--norc", "-c", recoveryRestoreRunbook(t))
		if !strings.Contains(output, "injected git status failure") {
			t.Fatalf("failure did not reach git status: %s", output)
		}
		if _, err := os.Lstat(filepath.Join(root, "restored")); !os.IsNotExist(err) {
			t.Fatalf("failed status check allowed restoration: %v", err)
		}
	})
	if puts.Load() != priorPuts {
		t.Fatal("rescue workflow uploaded remote objects")
	}
	if data, err := os.ReadFile(config); err != nil || string(data) != string(originalConfig) {
		t.Fatalf("rescue workflow changed preserved config: %v", err)
	}
}

func runRecoveryRestoreRunbook(t *testing.T, environment []string) string {
	t.Helper()
	return runEnv(t, "", environment, "bash", "--noprofile", "--norc", "-c", recoveryRestoreRunbook(t))
}

func recoveryRestoreRunbook(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../docs/recovery-restore.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Split(string(data), "```bash\n")
	if len(blocks) != 2 {
		t.Fatal("recovery runbook must have exactly one executable Bash block")
	}
	block, _, ok := strings.Cut(blocks[1], "\n```")
	if !ok {
		t.Fatal("unterminated runbook Bash block")
	}
	return block
}
