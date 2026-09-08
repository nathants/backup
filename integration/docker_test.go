package integration

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	libsodium "github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

const (
	defaultDockerImage       = "backup-test:rewrite"
	defaultDockerClientImage = "backup-test:integration-client"
	dockerRunLabelKey        = "backup.integration.run"
	testBucket               = "backup-test"
	testRegion               = "us-east-1"
	accessKey                = "backup-access"
	secretKey                = "backup-secret"
)

var (
	dockerImage       = environmentOrDefault("BACKUP_DOCKER_SERVER_IMAGE", defaultDockerImage)
	dockerClientImage = environmentOrDefault("BACKUP_DOCKER_CLIENT_IMAGE", defaultDockerClientImage)
	dockerRunID       = environmentOrDefault("BACKUP_DOCKER_RUN_ID", fmt.Sprintf("direct-%d", os.Getpid()))
	dockerRunLabel    = dockerRunLabelKey + "=" + dockerRunID
	dockerBuildOnce   sync.Once
	dockerBuildOutput []byte
	dockerBuildErr    error
)

func environmentOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func dockerResourceName(prefix string) string {
	return fmt.Sprintf("%s-%s-%d", prefix, dockerRunID, time.Now().UnixNano())
}

func ensureDockerImages(t *testing.T, repoRoot string) {
	t.Helper()
	dockerBuildOnce.Do(func() {
		if os.Getenv("BACKUP_DOCKER_IMAGES_READY") == "1" {
			for _, image := range []string{dockerImage, dockerClientImage} {
				output, err := exec.Command("docker", "image", "inspect", image).CombinedOutput()
				if err != nil {
					dockerBuildOutput = append(dockerBuildOutput, output...)
					dockerBuildErr = fmt.Errorf("inspect prebuilt Docker image %s: %w", image, err)
					return
				}
			}
			return
		}
		for _, arguments := range [][]string{
			{"build", "--progress=plain", "-t", dockerImage, repoRoot},
			{"build", "--progress=plain", "--target", "integration-client", "-t", dockerClientImage, repoRoot},
		} {
			command := exec.Command("docker", arguments...)
			var output bytes.Buffer
			stream := io.MultiWriter(&output, os.Stderr)
			command.Stdout = stream
			command.Stderr = stream
			err := command.Run()
			dockerBuildOutput = append(dockerBuildOutput, output.Bytes()...)
			if err != nil {
				dockerBuildErr = fmt.Errorf("docker %v: %w", arguments, err)
				return
			}
		}
	})
	if dockerBuildErr != nil {
		t.Fatalf("build shared Docker test images: %v: %s", dockerBuildErr, dockerBuildOutput)
	}
}

type dockerHarness struct {
	t         *testing.T
	container string
	volume    string
	certDir   string
	port      string
	client    *http.Client
	dataMount []string
	relay     *tcpRelay
}

type tcpRelay struct {
	listener net.Listener
	mutex    sync.RWMutex
	target   string
}

func newTCPRelay(t *testing.T) *tcpRelay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &tcpRelay{listener: listener}
	go relay.serve()
	return relay
}

func (relay *tcpRelay) serve() {
	for {
		connection, err := relay.listener.Accept()
		if err != nil {
			return
		}
		go relay.forward(connection)
	}
}

func (relay *tcpRelay) forward(client net.Conn) {
	relay.mutex.RLock()
	target := relay.target
	relay.mutex.RUnlock()
	if target == "" {
		_ = client.Close()
		return
	}
	server, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(server, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, server)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = server.Close()
	<-done
}

func (relay *tcpRelay) setTarget(target string) {
	relay.mutex.Lock()
	relay.target = target
	relay.mutex.Unlock()
}

func (relay *tcpRelay) port(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(relay.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func (relay *tcpRelay) close() {
	_ = relay.listener.Close()
}

func TestDockerProductionServerLifecycleAndImmutability(t *testing.T) {
	if os.Getenv("BACKUP_DOCKER_TEST") != "1" {
		t.Skip("set BACKUP_DOCKER_TEST=1 to run Docker integration")
	}
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ensureDockerImages(t, repoRoot)
	h := newDockerHarness(t)
	h.start()
	payload := []byte("docker durable object")
	key := objectKey(payload, 1)
	response := h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
	response = h.do(h.putRequest(key, []byte("different")))
	if response.StatusCode == http.StatusOK {
		t.Fatal("conditional overwrite succeeded")
	}
	closeBody(t, response)
	unconditional := h.putRequest(key, []byte("different"))
	unconditional.Header.Del("If-None-Match")
	h.sign(unconditional, accessKey, secretKey, []byte("different"))
	response = h.do(unconditional)
	if response.StatusCode == http.StatusOK {
		t.Fatal("unconditional overwrite succeeded")
	}
	closeBody(t, response)
	response = h.do(h.request(http.MethodDelete, key, nil))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("delete status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	h.restart()
	response = h.do(h.request(http.MethodGet, key, nil))
	if response.StatusCode != http.StatusOK || !bytes.Equal(closeBody(t, response), payload) {
		t.Fatalf("object did not survive container restart: status=%d", response.StatusCode)
	}
	head := h.request(http.MethodHead, key, nil)
	head.Header.Set("x-amz-checksum-mode", "ENABLED")
	h.sign(head, accessKey, secretKey, nil)
	response = h.do(head)
	if response.StatusCode != http.StatusOK || len(closeBody(t, response)) != 0 {
		t.Fatalf("checksum HEAD status=%d", response.StatusCode)
	}
	sha := sha256.Sum256(payload)
	if response.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(sha[:]) || response.Header.Get("x-amz-checksum-type") != "FULL_OBJECT" {
		t.Fatalf("checksum HEAD headers=%v", response.Header)
	}
	inspect := run(t, "", "docker", "inspect", "--format", "{{.Config.User}}", h.container)
	if strings.TrimSpace(inspect) != "65532:65532" {
		t.Fatalf("container user=%q", inspect)
	}
}

func TestDockerRealClientTwoMirrorBackupSyncRestoreAndRecover(t *testing.T) {
	if os.Getenv("BACKUP_DOCKER_TEST") != "1" {
		t.Skip("set BACKUP_DOCKER_TEST=1 to run Docker integration")
	}
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ensureDockerImages(t, repoRoot)
	binary := filepath.Join(t.TempDir(), "backup")
	run(t, repoRoot, "go", "build", "-o", binary, "./cmd/backup")

	firstMirror := newDockerHarness(t)
	secondMirror := newDockerHarness(t)
	firstMirror.start()
	secondMirror.start()

	workspace := t.TempDir()
	source := filepath.Join(workspace, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(workspace, "metadata.git")
	run(t, "", "git", "init", "--bare", "--object-format=sha256", "--initial-branch=main", remote)
	credentials := filepath.Join(workspace, "credentials")
	writeFile(t, credentials, []byte("[backup]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"\n"), 0o600)
	awsConfig := filepath.Join(workspace, "aws-config")
	writeFile(t, awsConfig, []byte(""), 0o600)
	config := filepath.Join(source, ".backup-config")
	configText := fmt.Sprintf("git-remote\t%s\nbranch\tmain\nmirror\ta\tbackup-server\ts3://%s\thttps://localhost:%s\t%s\tbackup\t%s\nmirror\tb\tbackup-server\ts3://%s\thttps://localhost:%s\t%s\tbackup\t%s\n",
		remote, testBucket, firstMirror.port, testRegion, filepath.Join(firstMirror.certDir, "ca.crt"), testBucket, secondMirror.port, testRegion, filepath.Join(secondMirror.certDir, "ca.crt"))
	writeFile(t, config, []byte(configText), 0o600)
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientEnvironment := cleanEnvironment(map[string]string{
		"AWS_SHARED_CREDENTIALS_FILE": credentials,
		"AWS_CONFIG_FILE":             awsConfig,
		"AWS_EC2_METADATA_DISABLED":   "true",
		"GIT_REMOTE_AWS_SECRETKEY":    hex.EncodeToString(secretKey),
	})
	backupCommand := func(arguments ...string) string {
		t.Helper()
		common := []string{"--root", source, "--config", config}
		arguments = append(arguments[:1], append(common, arguments[1:]...)...)
		return runEnv(t, "", clientEnvironment, binary, arguments...)
	}
	backupFailure := func(arguments ...string) string {
		t.Helper()
		common := []string{"--root", source, "--config", config}
		arguments = append(arguments[:1], append(common, arguments[1:]...)...)
		return runEnvFailure(t, "", clientEnvironment, binary, arguments...)
	}

	initOutput := backupCommand("init")
	if outputField(t, initOutput, "publication") != "local-only" || strings.Contains(initOutput, "complete-mirror\t") || strings.Contains(initOutput, "commit\t") {
		t.Fatalf("init claimed remote publication:\n%s", initOutput)
	}
	if refs := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "for-each-ref", "--format=%(objectname)")); refs != "" {
		t.Fatalf("init created remote history: %s", refs)
	}
	writeFile(t, filepath.Join(source, ".backup", ".publickeys"), []byte(hex.EncodeToString(publicKey)+"\n"), 0644)
	writeFile(t, filepath.Join(source, ".backup", "ignore"), []byte("^\\./\\.backup-config$\n"), 0o644)
	if err := os.Mkdir(filepath.Join(source, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	alpha := filepath.Join(source, "dir", "alpha file")
	writeFile(t, alpha, []byte("alpha contents\n"), 0o640)
	mtime := time.Unix(1_700_000_000, 123_456_789)
	if err := os.Chtimes(alpha, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "duplicate-one"), []byte("same bytes"), 0o600)
	writeFile(t, filepath.Join(source, "duplicate-two"), []byte("same bytes"), 0o600)
	if err := os.Symlink("dir/alpha file", filepath.Join(source, "alpha-link")); err != nil {
		t.Fatal(err)
	}

	addOutput := backupCommand("add")
	if !strings.Contains(addOutput, "entries\t4\n") || !strings.Contains(addOutput, "new-objects\t2\n") {
		t.Fatalf("unexpected add output:\n%s", addOutput)
	}
	diffOutput := backupCommand("diff")
	if !strings.Contains(diffOutput, "addition\t./dir/alpha file\tfile\t") || !strings.Contains(diffOutput, "addition\t./alpha-link\tsymlink\t") {
		t.Fatalf("unexpected diff output:\n%s", diffOutput)
	}

	secondMirror.stop()
	commitOutput := backupCommand("commit")
	firstCommit := outputField(t, commitOutput, "commit")
	genesis := strings.TrimSpace(run(t, "", "git", "--git-dir", remote, "rev-list", "--max-parents=0", firstCommit))
	if len(genesis) != 64 || firstCommit == genesis || !strings.Contains(commitOutput, "complete-mirror\ta\n") || !strings.Contains(commitOutput, "lagging-mirror\tb\n") {
		t.Fatalf("unexpected one-mirror commit output:\n%s", commitOutput)
	}
	secondMirror.start()
	syncOutput := backupCommand("sync", "--source", "a", "--destination", "b")
	if outputField(t, syncOutput, "commit") != firstCommit || outputUintField(t, syncOutput, "data-copied") == 0 || outputUintField(t, syncOutput, "metadata-copied") == 0 {
		t.Fatalf("unexpected sync output:\n%s", syncOutput)
	}
	verifyOutput := backupCommand("verify", "--minimum-mirrors", "2")
	if !strings.Contains(verifyOutput, "passed\t2\n") {
		t.Fatalf("two-mirror verification failed:\n%s", verifyOutput)
	}

	ledger := filepath.Join(source, ".backup", ".backup-state", "completion-ledger.json")
	if err := os.Remove(ledger); err != nil {
		t.Fatal(err)
	}
	if output := backupCommand("sync", "--source", "a", "--destination", "b"); outputUintField(t, output, "data-copied") != 0 || outputUintField(t, output, "metadata-copied") != 0 {
		t.Fatalf("ledger rebuild unexpectedly copied objects:\n%s", output)
	}
	backupCommand("sync", "--source", "b", "--destination", "a")
	resetCandidate := filepath.Join(source, "reset candidate")
	writeFile(t, resetCandidate, []byte("must not be committed\n"), 0o600)
	backupCommand("add")
	if output := backupCommand("reset"); strings.TrimSpace(output) != "reset" {
		t.Fatalf("unexpected reset output: %q", output)
	}
	if err := os.Remove(resetCandidate); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(source, "second revision"), []byte("new revision\n"), 0o644)
	backupCommand("add")
	secondCommitOutput := backupCommand("commit")
	secondCommit := outputField(t, secondCommitOutput, "commit")
	if secondCommit == firstCommit || !strings.Contains(secondCommitOutput, "complete-mirror\ta\n") || !strings.Contains(secondCommitOutput, "complete-mirror\tb\n") {
		t.Fatalf("unexpected second commit output:\n%s", secondCommitOutput)
	}

	findOutput := backupCommand("find", "alpha", firstCommit)
	if outputField(t, findOutput, "commit") != firstCommit || !strings.Contains(findOutput, "./alpha-link\tsymlink\t") || !strings.Contains(findOutput, "./dir/alpha file\tfile\t") {
		t.Fatalf("unexpected find output:\n%s", findOutput)
	}
	target := filepath.Join(workspace, "restore")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	dryRun := backupCommand("restore", "--target", target, "--dry-run", "^\\./", "HEAD")
	if !strings.Contains(dryRun, "plan\tnew\tfile\t./dir/alpha file\n") {
		t.Fatalf("unexpected restore dry-run output:\n%s", dryRun)
	}
	restoreOutput := backupCommand("restore", "--target", target, "^\\./", "HEAD")
	if outputField(t, restoreOutput, "snapshot-commit") != secondCommit || !strings.Contains(restoreOutput, "published\t./alpha-link\n") {
		t.Fatalf("unexpected restore output:\n%s", restoreOutput)
	}
	assertFile(t, filepath.Join(target, "dir", "alpha file"), []byte("alpha contents\n"), 0o640, mtime.UnixNano())
	assertFile(t, filepath.Join(target, "second revision"), []byte("new revision\n"), 0o644, -1)
	linkTarget, err := os.Readlink(filepath.Join(target, "alpha-link"))
	if err != nil || linkTarget != "dir/alpha file" {
		t.Fatalf("restored symlink target=%q err=%v", linkTarget, err)
	}
	firstDuplicate, err := os.Stat(filepath.Join(target, "duplicate-one"))
	if err != nil {
		t.Fatal(err)
	}
	secondDuplicate, err := os.Stat(filepath.Join(target, "duplicate-two"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(firstDuplicate, secondDuplicate) {
		t.Fatal("deduplicated files were restored as one inode")
	}

	packHash, partNumber := firstPackPart(t, source, secondCommit)
	repairOutput := runEnv(t, "", clientEnvironment, binary, "repair", "data", "--root", source, "--config", config, "--source", "a", packHash, strconv.FormatUint(uint64(partNumber), 10))
	repairCommit := outputField(t, repairOutput, "commit")
	if repairCommit == secondCommit || outputField(t, repairOutput, "old-object-id") == outputField(t, repairOutput, "new-object-id") {
		t.Fatalf("unexpected data repair output:\n%s", repairOutput)
	}
	metadataRepair := runEnv(t, "", clientEnvironment, binary, "repair", "metadata", "--root", source, "--config", config, "--destination", "a", "--revision", repairCommit)
	if outputField(t, metadataRepair, "tip") != repairCommit || outputField(t, metadataRepair, "manifest-object-id") == "" {
		t.Fatalf("unexpected metadata repair output:\n%s", metadataRepair)
	}
	secondCommit = repairCommit

	firstMirror.stop()
	firstMirror.start()
	secondMirror.stop()
	secondMirror.start()
	if output := backupCommand("verify", "--minimum-mirrors", "2"); !strings.Contains(output, "passed\t2\n") {
		t.Fatalf("verification after server restart failed:\n%s", output)
	}

	unavailableRemote := remote + ".unavailable"
	if err := os.Rename(remote, unavailableRemote); err != nil {
		t.Fatal(err)
	}
	listOutput := backupCommand("recover", "--mirror", "a", "--list")
	if !strings.Contains(listOutput, "available-tip\t"+genesis+"\n") || !strings.Contains(listOutput, "available-tip\t"+secondCommit+"\n") {
		t.Fatalf("unexpected recovery list:\n%s", listOutput)
	}
	recovered := filepath.Join(workspace, "recovered.git")
	recoverOutput := backupCommand("recover", "--mirror", "a", "--destination", recovered)
	if outputField(t, recoverOutput, "recovered-tip") != secondCommit {
		t.Fatalf("unexpected latest recovery output:\n%s", recoverOutput)
	}
	if strings.TrimSpace(run(t, "", "git", "--git-dir", recovered, "rev-parse", "refs/backup/recovered-tip")) != secondCommit {
		t.Fatal("recovered repository tip disagrees with the backup revision")
	}
	earlier := filepath.Join(workspace, "earlier.git")
	earlierOutput := backupCommand("recover", "--mirror", "b", "--tip", genesis, "--destination", earlier)
	if outputField(t, earlierOutput, "recovered-tip") != genesis {
		t.Fatalf("unexpected anchored recovery output:\n%s", earlierOutput)
	}

	if output := backupFailure("verify", "--minimum-mirrors", "1"); !strings.Contains(output, "fetch") {
		t.Fatalf("primary-remote outage was not observed by ordinary verification:\n%s", output)
	}
	// The runbook must work with neither the old checkout/source nor another
	// mirror available. Keep their preserved bytes out of the rescue paths.
	if err := os.Rename(source, source+".unavailable"); err != nil {
		t.Fatal(err)
	}
	secondMirror.stop()
	rescueConfig := filepath.Join(workspace, "rescue-trusted-config")
	writeFile(t, rescueConfig, []byte(configText), 0o600)
	anchoredData := filepath.Join(workspace, "anchored-data.git")
	output := runEnv(t, "", clientEnvironment, binary, "recover", "--root", source, "--config", rescueConfig,
		"--mirror", "a", "--tip", firstCommit, "--destination", anchoredData)
	if outputField(t, output, "recovered-tip") != firstCommit {
		t.Fatalf("anchored data recovery selected wrong tip: %s", output)
	}
	for _, item := range []struct{ repository, tip string }{{recovered, secondCommit}, {anchoredData, firstCommit}} {
		root := filepath.Join(workspace, "rescue-"+item.tip)
		environment := append(append([]string(nil), clientEnvironment...),
			"BACKUP_BIN="+binary, "RECOVERED="+item.repository, "TIP="+item.tip,
			"BRANCH=main", "RESCUE_ROOT="+root, "TRUSTED_CONFIG="+rescueConfig)
		output := runRecoveryRestoreRunbook(t, environment)
		if outputField(t, output, "snapshot-commit") != item.tip {
			t.Fatalf("runbook restored wrong tip: %s", output)
		}
		target := filepath.Join(root, "restored")
		assertFile(t, filepath.Join(target, "dir", "alpha file"), []byte("alpha contents\n"), 0o640, mtime.UnixNano())
		assertFile(t, filepath.Join(target, "duplicate-one"), []byte("same bytes"), 0o600, -1)
		assertFile(t, filepath.Join(target, "duplicate-two"), []byte("same bytes"), 0o600, -1)
		if link, err := os.Readlink(filepath.Join(target, "alpha-link")); err != nil || link != "dir/alpha file" {
			t.Fatalf("runbook symlink=%q, %v", link, err)
		}
		if item.tip == secondCommit {
			assertFile(t, filepath.Join(target, "second revision"), []byte("new revision\n"), 0o644, -1)
		} else if _, err := os.Lstat(filepath.Join(target, "second revision")); !os.IsNotExist(err) {
			t.Fatalf("historical rescue included later content: %v", err)
		}
	}
	for _, unavailable := range []string{source, remote} {
		if _, err := os.Lstat(unavailable); !os.IsNotExist(err) {
			t.Fatalf("original path became available during rescue: %s: %v", unavailable, err)
		}
	}
}

func TestDockerWholeRootClientContainerAgainstSeparateServer(t *testing.T) {
	if os.Getenv("BACKUP_DOCKER_TEST") != "1" {
		t.Skip("set BACKUP_DOCKER_TEST=1 to run Docker integration")
	}
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ensureDockerImages(t, repoRoot)
	server := newDockerHarness(t)
	server.start()

	workspace := t.TempDir()
	remote := filepath.Join(workspace, "metadata.git")
	run(t, "", "git", "init", "--bare", "--object-format=sha256", "--initial-branch=main", remote)
	configDirectory := filepath.Join(workspace, "config")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(configDirectory, "credentials")
	writeFile(t, credentials, []byte("[backup]\naws_access_key_id = "+accessKey+"\naws_secret_access_key = "+secretKey+"\n"), 0o600)
	writeFile(t, filepath.Join(configDirectory, "aws-config"), nil, 0o600)
	caPath := filepath.Join(configDirectory, "ca.crt")
	ca, err := os.ReadFile(filepath.Join(server.certDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, caPath, ca, 0o644)
	config := fmt.Sprintf("git-remote\t/metadata.git\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://%s\thttps://localhost:%s\t%s\tbackup\t/test-config/ca.crt\n", testBucket, server.port, testRegion)
	writeFile(t, filepath.Join(configDirectory, "backup-config"), []byte(config), 0o600)
	stateVolume := dockerResourceName("backup-client-state")
	run(t, "", "docker", "volume", "create", "--label", dockerRunLabel, stateVolume)
	t.Cleanup(func() { _, _ = exec.Command("docker", "volume", "rm", "-f", stateVolume).CombinedOutput() })
	restoreRoot := filepath.Join(workspace, "restore")
	if err := os.Mkdir(restoreRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Two Docker bind mounts of the same filesystem: st_dev cannot identify
	// the boundary at bind, while an ordinary nested directory is not a mount.
	mountSource := filepath.Join(workspace, "mount-source")
	if err := os.MkdirAll(filepath.Join(mountSource, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mountSource, "bind"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(mountSource, "nested", "content"), []byte("bind mount fixture\n"), 0o600)
	devices := strings.Fields(run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel,
		"-v", mountSource+":/fixture-mounted:ro",
		"-v", filepath.Join(mountSource, "nested")+":/fixture-mounted/bind:ro",
		"--entrypoint", "stat", dockerClientImage, "-c", "%d", "/fixture-mounted", "/fixture-mounted/bind"))
	if len(devices) != 2 || devices[0] != devices[1] {
		t.Fatalf("bind-mount fixture must share st_dev: %v", devices)
	}
	runClient := func(arguments ...string) string {
		t.Helper()
		dockerArguments := []string{
			"run", "--rm", "--label", dockerRunLabel, "--network", "host",
			"-v", mountSource + ":/fixture-mounted:ro",
			"-v", filepath.Join(mountSource, "nested") + ":/fixture-mounted/bind:ro",
			"-v", stateVolume + ":/.backup",
			"-v", remote + ":/metadata.git",
			"-v", configDirectory + ":/test-config:ro",
			"-v", restoreRoot + ":/restore",
			"-e", "AWS_SHARED_CREDENTIALS_FILE=/test-config/credentials",
			"-e", "AWS_CONFIG_FILE=/test-config/aws-config",
			"-e", "AWS_EC2_METADATA_DISABLED=true",
			"-e", "GIT_REMOTE_AWS_SECRETKEY=" + hex.EncodeToString(secretKey),
			"--entrypoint", "/usr/local/bin/backup", dockerClientImage,
		}
		dockerArguments = append(dockerArguments, arguments...)
		return run(t, "", "docker", dockerArguments...)
	}
	common := []string{"--root", "/", "--config", "/test-config/backup-config"}
	withCommon := func(command string, arguments ...string) []string {
		result := []string{command}
		result = append(result, common...)
		return append(result, arguments...)
	}

	initOutput := runClient(withCommon("init")...)
	if outputField(t, initOutput, "publication") != "local-only" || strings.Contains(initOutput, "commit\t") {
		t.Fatalf("unexpected whole-root init output:\n%s", initOutput)
	}
	run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "-v", stateVolume+":/.backup", "--entrypoint", "/bin/sh", dockerClientImage, "-c", "printf '%s\\n' "+hex.EncodeToString(publicKey)+" > /.backup/.publickeys && chmod 0644 /.backup/.publickeys")
	ignore := `printf '%s\n' '^\./(\.dockerenv|etc|go|metadata\.git|out|restore|src|test-config|usr|var)(/|$)' > /.backup/ignore && chmod 0644 /.backup/ignore`
	run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "-v", stateVolume+":/.backup", "--entrypoint", "/bin/sh", dockerClientImage, "-c", ignore)
	addOutput := runClient(withCommon("add")...)
	if !strings.Contains(addOutput, "entries\t") {
		t.Fatalf("whole-root scan did not report entries:\n%s", addOutput)
	}
	for _, path := range []string{"./fixture-mounted", "./fixture-mounted/bind"} {
		if strings.Count(addOutput, "mount-entered\t"+path+"\n") != 1 {
			t.Errorf("mount %s was not reported exactly once:\n%s", path, addOutput)
		}
	}
	if strings.Contains(addOutput, "mount-entered\t./fixture-mounted/nested\n") {
		t.Errorf("ordinary directory reported as a mount:\n%s", addOutput)
	}
	diffOutput := runClient(withCommon("diff")...)
	for _, path := range []string{"./fixture/root-only", "./fixture-mounted/nested/content", "./fixture-mounted/bind/content"} {
		if !strings.Contains(diffOutput, path+"\tfile\t") {
			t.Fatalf("whole-root fixture %s was not staged:\n%s", path, diffOutput)
		}
	}
	commitOutput := runClient(withCommon("commit")...)
	commit := outputField(t, commitOutput, "commit")
	if len(commit) != 64 || !strings.Contains(commitOutput, "complete-mirror\tlocal\n") {
		t.Fatalf("unexpected whole-root commit output:\n%s", commitOutput)
	}
	if output := runClient(withCommon("verify", "--minimum-mirrors", "1")...); !strings.Contains(output, "passed\t1\n") {
		t.Fatalf("whole-root verify failed:\n%s", output)
	}
	restoreOutput := runClient(withCommon("restore", "--target", "/restore", "^\\./fixture(/|-mounted/)", commit)...)
	if !strings.Contains(restoreOutput, "published\t./fixture/root-only\n") || !strings.Contains(restoreOutput, "published\t./fixture/root-link\n") {
		t.Fatalf("whole-root restore failed:\n%s", restoreOutput)
	}
	fixtureInfo, err := os.Stat(filepath.Join(mountSource, "nested", "content"))
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"nested", "bind"} {
		assertFile(t, filepath.Join(restoreRoot, "fixture-mounted", directory, "content"), []byte("bind mount fixture\n"), 0o600, fixtureInfo.ModTime().UnixNano())
	}
	assertFile(t, filepath.Join(restoreRoot, "fixture", "root-only"), []byte("whole-root fixture\n"), 0o600, 1_700_000_000_000_000_000)
	link, err := os.Readlink(filepath.Join(restoreRoot, "fixture", "root-link"))
	if err != nil || link != "root-only" {
		t.Fatalf("whole-root restored link=%q err=%v", link, err)
	}
	server.stop()
	server.start()
	if output := runClient(withCommon("verify", "--minimum-mirrors", "1")...); !strings.Contains(output, "passed\t1\n") {
		t.Fatalf("whole-root verify after server restart failed:\n%s", output)
	}
}

func newDockerHarness(t *testing.T) *dockerHarness {
	t.Helper()
	root := t.TempDir()
	certDir := filepath.Join(root, "tls")
	if err := os.Mkdir(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(certDir, "openssl.cnf")
	config := `[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=backup test CA
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, "", "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", configPath, "-keyout", filepath.Join(certDir, "ca.key"), "-out", filepath.Join(certDir, "ca.crt"))
	run(t, "", "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", filepath.Join(certDir, "server.key"), "-out", filepath.Join(certDir, "server.csr"))
	run(t, "", "openssl", "x509", "-req", "-days", "2", "-in", filepath.Join(certDir, "server.csr"), "-CA", filepath.Join(certDir, "ca.crt"), "-CAkey", filepath.Join(certDir, "ca.key"), "-CAcreateserial", "-extfile", configPath, "-extensions", "server", "-out", filepath.Join(certDir, "server.crt"))
	for _, name := range []string{"ca.crt", "server.crt"} {
		if err := os.Chmod(filepath.Join(certDir, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"ca.key", "server.key"} {
		if err := os.Chmod(filepath.Join(certDir, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	volume := dockerResourceName("backup-test")
	run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "--user", "0", "--entrypoint", "/bin/sh", "-v", certDir+":/tls", dockerImage, "-c", "chown 65532:65532 /tls/server.key && chmod 0600 /tls/server.key")
	run(t, "", "docker", "volume", "create", "--label", dockerRunLabel, volume)
	run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "--user", "0", "--entrypoint", "/bin/chown", "-v", volume+":/data", dockerImage, "65532:65532", "/data")
	client := &http.Client{Timeout: 10 * time.Second}
	relay := newTCPRelay(t)
	h := &dockerHarness{t: t, volume: volume, certDir: certDir, port: relay.port(t), client: client, relay: relay}
	t.Cleanup(func() {
		h.remove()
		_, _ = exec.Command("docker", "volume", "rm", "-f", volume).CombinedOutput()
	})
	return h
}

func (h *dockerHarness) start() {
	h.t.Helper()
	if h.container != "" {
		run(h.t, "", "docker", "start", h.container)
		h.updateRelayTarget()
		h.waitReady("start")
		return
	}

	name := dockerResourceName("backup-test")
	arguments := []string{"run", "-d", "--name", name, "--label", dockerRunLabel, "-p", "127.0.0.1::8443"}
	if len(h.dataMount) != 0 {
		arguments = append(arguments, h.dataMount...)
	} else {
		arguments = append(arguments, "-v", h.volume+":/data")
	}
	arguments = append(arguments,
		"-v", h.certDir+":/tls:ro",
		"-e", "BACKUP_SERVER_ACCESS_KEY="+accessKey,
		"-e", "BACKUP_SERVER_SECRET_KEY="+secretKey,
		dockerImage,
		"--listen", ":8443", "--data-root", "/data", "--bucket", testBucket,
		"--region", testRegion, "--tls-cert", "/tls/server.crt", "--tls-key", "/tls/server.key")
	h.container = name
	_ = run(h.t, "", "docker", arguments...)
	h.updateRelayTarget()
	ca, err := os.ReadFile(filepath.Join(h.certDir, "ca.crt"))
	if err != nil {
		h.t.Fatal(err)
	}
	h.client = trustedClient(h.t, ca)
	h.waitReady("create")
}

func (h *dockerHarness) updateRelayTarget() {
	h.t.Helper()
	mapping := strings.TrimSpace(run(h.t, "", "docker", "port", h.container, "8443/tcp"))
	const addressPrefix = "127.0.0.1:"
	port := strings.TrimPrefix(mapping, addressPrefix)
	if !strings.HasPrefix(mapping, addressPrefix) || port == "" || strings.Contains(port, "\n") {
		h.t.Fatalf("unexpected Docker port mapping %q", mapping)
	}
	h.relay.setTarget(mapping)
}

func (h *dockerHarness) waitReady(action string) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		request := h.request(http.MethodGet, objectKey([]byte("readiness-probe"), 9), nil)
		response, err := h.client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("container server did not become ready after %s: %v\n%s", action, lastErr, h.diagnostics())
}

func (h *dockerHarness) diagnostics() string {
	var result strings.Builder
	for _, arguments := range [][]string{
		{"inspect", "--format", "{{json .State}} {{json .NetworkSettings.Ports}}", h.container},
		{"logs", "--tail", "200", h.container},
	} {
		output, err := exec.Command("docker", arguments...).CombinedOutput()
		fmt.Fprintf(&result, "docker %s: %v\n%s\n", strings.Join(arguments, " "), err, output)
	}
	return result.String()
}

func (h *dockerHarness) restart() {
	h.t.Helper()
	if h.container == "" {
		h.t.Fatal("cannot restart an absent container")
	}
	h.stop()
	h.start()
}

func (h *dockerHarness) stop() {
	h.t.Helper()
	if h.container == "" {
		return
	}
	h.relay.setTarget("")
	h.client.CloseIdleConnections()
	run(h.t, "", "docker", "stop", h.container)
}

func (h *dockerHarness) remove() {
	h.relay.setTarget("")
	h.client.CloseIdleConnections()
	if h.container != "" {
		_, _ = exec.Command("docker", "rm", "-f", h.container).CombinedOutput()
		h.container = ""
	}
	h.relay.close()
}

func trustedClient(t *testing.T, ca []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("test CA invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func objectKey(data []byte, id byte) string {
	hash := blake2b.Sum512(data)
	return "objects/" + hex.EncodeToString(hash[:]) + "/" + strings.Repeat(hex.EncodeToString([]byte{id}), 16)
}

func (h *dockerHarness) putRequest(key string, body []byte) *http.Request {
	request := h.request(http.MethodPut, key, body)
	md5sum := md5.Sum(body)
	sha := sha256.Sum256(body)
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(md5sum[:]))
	request.Header.Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(sha[:]))
	request.Header.Set("x-amz-sdk-checksum-algorithm", "SHA256")
	h.sign(request, accessKey, secretKey, body)
	return request
}

func (h *dockerHarness) request(method, key string, body []byte) *http.Request {
	request, err := http.NewRequest(method, "https://localhost:"+h.port+"/"+testBucket+"/"+key, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodDelete {
		request.Body = nil
		request.ContentLength = 0
	}
	h.sign(request, accessKey, secretKey, body)
	return request
}

func (h *dockerHarness) sign(request *http.Request, access, secret string, body []byte) {
	payload := sha256.Sum256(body)
	hash := hex.EncodeToString(payload[:])
	request.Header.Set("x-amz-content-sha256", hash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: access, SecretAccessKey: secret}, request, hash, "s3", testRegion, time.Now().UTC()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *dockerHarness) do(request *http.Request) *http.Response {
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	return response
}

func closeBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path string, expected []byte, mode os.FileMode, mtimeNS int64) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("%s contents=%q, want %q", path, actual, expected)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("%s mode=%04o, want %04o", path, info.Mode().Perm(), mode)
	}
	if mtimeNS >= 0 && info.ModTime().UnixNano() != mtimeNS {
		t.Fatalf("%s mtime=%d, want %d", path, info.ModTime().UnixNano(), mtimeNS)
	}
}

func firstPackPart(t *testing.T, root, revision string) (string, uint64) {
	t.Helper()
	output := run(t, "", "git", "-C", filepath.Join(root, ".backup"), "show", revision+":packs.tsv")
	line, _, ok := strings.Cut(output, "\n")
	if !ok || line == "" {
		t.Fatalf("revision %s has no pack rows", revision)
	}
	fields := strings.Split(line, "\t")
	if len(fields) != 8 {
		t.Fatalf("invalid packs.tsv row %q", line)
	}
	part, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		t.Fatalf("invalid pack part number %q: %v", fields[1], err)
	}
	return fields[0], part
}

func outputField(t *testing.T, output, name string) string {
	t.Helper()
	prefix := name + "\t"
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("output lacks field %q:\n%s", name, output)
	return ""
}

func outputUintField(t *testing.T, output, name string) uint64 {
	t.Helper()
	value, err := strconv.ParseUint(outputField(t, output, name), 10, 64)
	if err != nil {
		t.Fatalf("output field %q is not unsigned decimal: %v", name, err)
	}
	return value
}

func cleanEnvironment(overrides map[string]string) []string {
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "BACKUP_") || strings.HasPrefix(name, "GIT_REMOTE_AWS_") {
			continue
		}
		if _, replaced := overrides[name]; replaced {
			continue
		}
		environment = append(environment, entry)
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	return environment
}

func runEnv(t *testing.T, directory string, environment []string, command string, arguments ...string) string {
	t.Helper()
	cmd := exec.Command(command, arguments...)
	cmd.Dir = directory
	cmd.Env = environment
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", command, arguments, err, output)
	}
	return string(output)
}

func runEnvFailure(t *testing.T, directory string, environment []string, command string, arguments ...string) string {
	t.Helper()
	cmd := exec.Command(command, arguments...)
	cmd.Dir = directory
	cmd.Env = environment
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("%s %v unexpectedly succeeded: %s", command, arguments, output)
	}
	return string(output)
}

func run(t *testing.T, directory string, command string, arguments ...string) string {
	t.Helper()
	cmd := exec.Command(command, arguments...)
	cmd.Dir = directory
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", command, arguments, err, output)
	}
	return string(output)
}
