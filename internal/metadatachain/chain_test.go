package metadatachain

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/repository"
	"github.com/nathants/go-libsodium"
)

func TestBuildManifestPartsAndDecryptBundle(t *testing.T) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repoPath := initBundleRepo(t)
	tip := strings.TrimSpace(run(t, repoPath, "rev-parse", "HEAD"))
	repo := &repository.Managed{Directory: repoPath, Branch: "main"}
	result, err := Build(repo, "123e4567-e89b-42d3-a456-426614174000", "", tip, 0, [][]byte{publicKey}, filepath.Join(t.TempDir(), "stage"), 128, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Kind != format.BundleFull || result.Manifest.BaseCommit != "-" || result.Manifest.TipCommit != tip || len(result.Parts) < 2 {
		t.Fatalf("result=%#v", result)
	}
	manifestData, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := format.ParseMetadataManifest(bytes.NewReader(manifestData), format.DefaultLimits())
	if err != nil || parsed.TipCommit != tip {
		t.Fatalf("manifest=%#v err=%v", parsed, err)
	}
	var encrypted bytes.Buffer
	for _, part := range result.Parts {
		data, err := os.ReadFile(part.Path)
		if err != nil {
			t.Fatal(err)
		}
		encrypted.Write(data)
	}
	var bundle bytes.Buffer
	if err := Decrypt(bytes.NewReader(encrypted.Bytes()), result.Manifest.BundleHash, result.Manifest.BundleSize, secretKey, &bundle); err != nil {
		t.Fatal(err)
	}
	originalPath := filepath.Join(t.TempDir(), "original.bundle")
	if err := repo.CreateBundle("", tip, originalPath); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.Bytes(), original) {
		t.Fatal("decrypted bundle mismatch")
	}
	if err := repo.VerifyBundle(originalPath); err != nil {
		t.Fatal(err)
	}
}

func TestIncrementalManifest(t *testing.T) {
	libsodium.Init()
	publicKey, _, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repoPath := initBundleRepo(t)
	base := strings.TrimSpace(run(t, repoPath, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(repoPath, "file"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repoPath, "add", "file")
	run(t, repoPath, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-m", "two")
	tip := strings.TrimSpace(run(t, repoPath, "rev-parse", "HEAD"))
	result, err := Build(&repository.Managed{Directory: repoPath, Branch: "main"}, "123e4567-e89b-42d3-a456-426614174000", base, tip, 1, [][]byte{publicKey}, filepath.Join(t.TempDir(), "stage"), 1<<20, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Kind != format.BundleIncremental || result.Manifest.BaseCommit != base || result.Manifest.Sequence != 1 {
		t.Fatalf("manifest=%#v", result.Manifest)
	}
}

func TestBuildEnforcesCiphertextBudgetAndCleansParts(t *testing.T) {
	libsodium.Init()
	publicKey, _, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	repoPath := initBundleRepo(t)
	tip := strings.TrimSpace(run(t, repoPath, "rev-parse", "HEAD"))
	stage := filepath.Join(t.TempDir(), "stage")
	_, err = Build(&repository.Managed{Directory: repoPath, Branch: "main"}, "123e4567-e89b-42d3-a456-426614174000", "", tip, 0, [][]byte{publicKey}, stage, 128, 1)
	if err == nil || !strings.Contains(err.Error(), "staging budget") {
		t.Fatalf("tiny ciphertext budget was accepted: %v", err)
	}
	entries, readErr := os.ReadDir(stage)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "metadata-part-") || entry.Name() == "metadata.bundle" || entry.Name() == "metadata.bundle.encrypted" {
			t.Fatalf("failed streaming build retained payload workspace %q", entry.Name())
		}
	}
}

func TestDecryptRejectsTrailingOrWrongHash(t *testing.T) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := encrypt(bytes.NewReader([]byte("bundle")), [][]byte{publicKey}, &encrypted); err != nil {
		t.Fatal(err)
	}
	object := hashBytes(encrypted.Bytes())
	trailing := append(append([]byte(nil), encrypted.Bytes()...), 0)
	trailingObject := hashBytes(trailing)
	if err := Decrypt(bytes.NewReader(trailing), trailingObject.BLAKE2b, trailingObject.Size, secretKey, io.Discard); err == nil {
		t.Fatal("trailing ciphertext accepted")
	}
	if err := Decrypt(bytes.NewReader(encrypted.Bytes()), strings.Repeat("0", 128), object.Size, secretKey, io.Discard); err == nil {
		t.Fatal("wrong hash accepted")
	}
}

func initBundleRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run(t, "", "init", "--object-format=sha256", "--initial-branch=main", repo)
	if err := os.WriteFile(filepath.Join(repo, "file"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, repo, "add", "file")
	run(t, repo, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-m", "one")
	return repo
}

func run(t *testing.T, repo string, args ...string) string {
	t.Helper()
	if repo != "" {
		args = append([]string{"-C", repo}, args...)
	}
	command := exec.Command("git", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return string(output)
}
