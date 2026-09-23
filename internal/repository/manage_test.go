package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

func TestOpenManagedRejectsRepositorySymlink(t *testing.T) {
	remote := filepath.Join(t.TempDir(), "remote.git")
	target := filepath.Join(t.TempDir(), "metadata")
	if _, err := Initialize(target, remote, "main"); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "metadata-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenManaged(link, remote, "main"); err == nil {
		t.Fatal("opened metadata repository through a symlink")
	}
}

func TestManagedRepositoryCreatesValidCommitsWithoutUsingIndex(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "metadata")
	repo, err := Initialize(directory, filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	blobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", blobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.Materialize(blobs); err != nil {
		t.Fatal(err)
	}
	history, err := (Validator{Repo: directory, Limits: format.DefaultLimits()}).ValidateHistory(genesis)
	if err != nil {
		t.Fatal(err)
	}
	if history.Len() != 1 {
		t.Fatalf("history=%d", history.Len())
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	status, err := repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Clean {
		t.Fatalf("repo not clean: %#v", status)
	}
	if _, err := os.Stat(filepath.Join(directory, ".backup-state")); !os.IsNotExist(err) {
		t.Fatalf("state unexpectedly exists: %v", err)
	}

	changed := cloneBlobs(blobs)
	changed["ignore"] = []byte("^\\./tmp(?:/|$)\n")
	child, err := repo.CreateCommit(genesis, changed, "config update")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(child, genesis); err != nil {
		t.Fatal(err)
	}
	validator := Validator{Repo: directory, Limits: format.DefaultLimits(), CachePath: filepath.Join(t.TempDir(), "validation-cache")}
	history, err = validator.ValidateHistory(child)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := history.Tip()
	if err != nil || history.Len() != 2 || tip.Transition != TransitionOrdinary {
		t.Fatalf("history count=%d tip=%#v err=%v", history.Len(), tip, err)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	cachedHistory, err := validator.ValidateHistory(child)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cachedHistory.Close() }()
	cachedTip, err := cachedHistory.Tip()
	if err != nil || cachedTip.Transition != TransitionOrdinary {
		t.Fatalf("cached transition=%v err=%v", cachedTip.Transition, err)
	}
}

func TestValidatedHistoryRejectsReusedMirrorName(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "metadata")
	repo, err := Initialize(directory, filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	genesisBlobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", genesisBlobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	removedBlobs := cloneBlobs(genesisBlobs)
	removedBlobs["mirrors.tsv"] = nil
	removed, err := repo.CreateCommit(genesis, removedBlobs, "remove mirror")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(removed, genesis); err != nil {
		t.Fatal(err)
	}
	reboundBlobs := cloneBlobs(removedBlobs)
	rebound, err := format.MarshalMirrors([]format.Mirror{{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://other/repository", Endpoint: "https://other.example", Region: "us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	reboundBlobs["mirrors.tsv"] = rebound
	reused, err := repo.CreateCommit(removed, reboundBlobs, "reuse mirror name")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(reused, removed); err != nil {
		t.Fatal(err)
	}
	if _, err := (Validator{Repo: directory, Limits: format.DefaultLimits()}).ValidateHistory(reused); err == nil || !strings.Contains(err.Error(), "rebound or reused") {
		t.Fatalf("reused mirror name was accepted: %v", err)
	}
}

func TestAcceptCommitUsesCompareAndSwap(t *testing.T) {
	repo, err := Initialize(filepath.Join(t.TempDir(), "metadata"), filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := repo.CreateCommit("", validGenesisBlobs(t), "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err == nil {
		t.Fatal("stale CAS accepted")
	}
}

func TestPushUsesBranchSourceCompatibleWithGitRemoteHelpers(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	bin := t.TempDir()
	helper := filepath.Join(bin, "git-remote-compat")
	script := `#!/bin/sh
if [ "$AWS_REGION" != us-east-1 ] || [ "$AWS_DEFAULT_REGION" != us-west-2 ]; then
    printf 'AWS region environment was not preserved\n' >&2
    exit 1
fi
while IFS= read -r line; do
    case "$line" in
        capabilities)
            printf 'push\n\n'
            ;;
        'list for-push')
            printf '\n'
            ;;
        'push refs/heads/main:refs/heads/main')
            printf 'ok refs/heads/main\n\n'
            ;;
        push*)
            printf 'error refs/heads/main incompatible-source\n\n'
            ;;
        '')
            exit 0
            ;;
    esac
done
`
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	repo, err := Initialize(filepath.Join(t.TempDir(), "metadata"), "compat::opaque", "main")
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := repo.CreateCommit("", validGenesisBlobs(t), "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	changed := cloneBlobs(validGenesisBlobs(t))
	changed["ignore"] = []byte("x\n")
	unaccepted, err := repo.CreateCommit(genesis, changed, "unaccepted")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Push(unaccepted, genesis); err == nil || !strings.Contains(err.Error(), "disagrees with push commit") {
		t.Fatalf("pushed a commit not named by the local branch: %v", err)
	}
	if err := repo.Push(genesis, ""); err != nil {
		t.Fatalf("push through branch-only remote helper: %v", err)
	}
}

func TestMaterializeRejectsDirtyOrUntrackedMetadata(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "metadata")
	repo, err := Initialize(directory, filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	blobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", blobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.Materialize(blobs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Clean || !strings.Contains(strings.Join(status.Paths, ","), "unexpected") {
		t.Fatalf("status=%#v", status)
	}
}

func TestStatusRejectsUnexpectedCanonicalBlobType(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "metadata")
	repo, err := Initialize(directory, filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	blobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", blobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.Materialize(blobs); err != nil {
		t.Fatal(err)
	}
	ignore := filepath.Join(directory, "ignore")
	if err := os.Remove(ignore); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(ignore, 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := repo.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Clean || strings.Join(status.Paths, ",") != "ignore" {
		t.Fatalf("FIFO canonical metadata blob was not reported dirty: %#v", status)
	}
}

func TestBundleCreationAndVerification(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "metadata")
	repo, err := Initialize(directory, filepath.Join(t.TempDir(), "remote.git"), "main")
	if err != nil {
		t.Fatal(err)
	}
	blobs := validGenesisBlobs(t)
	genesis, err := repo.CreateCommit("", blobs, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AcceptCommit(genesis, ""); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(t.TempDir(), "full.bundle")
	if err := repo.CreateBundle("", genesis, full); err != nil {
		t.Fatal(err)
	}
	if err := repo.VerifyBundle(full); err != nil {
		t.Fatal(err)
	}

	changed := cloneBlobs(blobs)
	changed["ignore"] = []byte("x\n")
	child, err := repo.CreateCommit(genesis, changed, "child")
	if err != nil {
		t.Fatal(err)
	}
	incremental := filepath.Join(t.TempDir(), "incremental.bundle")
	if err := repo.CreateBundle(genesis, child, incremental); err != nil {
		t.Fatal(err)
	}
	if err := repo.VerifyBundle(incremental); err != nil {
		t.Fatal(err)
	}
}
