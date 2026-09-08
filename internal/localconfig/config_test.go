package localconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestLoadPinsCanonicalMirrorsAndRoleProfiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	data := "git-remote\t/tmp/remote.git\n" +
		"branch\tmain\n" +
		"mirror\tlocal\tbackup-server\ts3://backup-test/repo\thttps://localhost:8443\tus-east-1\twriter-local\treader-local\t/tmp/ca.pem\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.GitRemote != "/tmp/remote.git" || config.Branch != "main" || len(config.Mirrors) != 1 {
		t.Fatalf("config=%#v", config)
	}
	mirror := config.Mirrors[0]
	if mirror.Canonical.Name != "local" || mirror.WriterProfile != "writer-local" || mirror.ReaderProfile != "reader-local" || mirror.CAFile != "/tmp/ca.pem" {
		t.Fatalf("mirror=%#v", mirror)
	}
	canonical := []format.Mirror{mirror.Canonical}
	if err := config.RequireCanonicalMirrors(canonical); err != nil {
		t.Fatal(err)
	}
	canonical[0].Endpoint = "https://redirect.example"
	if err := config.RequireCanonicalMirrors(canonical); err == nil {
		t.Fatal("redirected mirror was accepted")
	}
}

func TestLoadRejectsMalformedUnsafeOrDuplicateConfig(t *testing.T) {
	validMirror := "mirror\tlocal\tbackup-server\ts3://backup-test/repo\thttps://localhost:8443\tus-east-1\tw\tr\t-\n"
	tests := map[string]string{
		"missing LF":    "git-remote\t/tmp/remote.git\nbranch\tmain",
		"unknown row":   "git-remote\t/tmp/remote.git\nbranch\tmain\nunknown\tx\n" + validMirror,
		"duplicate":     "git-remote\t/tmp/remote.git\ngit-remote\t/x\nbranch\tmain\n" + validMirror,
		"bad branch":    "git-remote\t/tmp/remote.git\nbranch\t-main\n" + validMirror,
		"no mirror":     "git-remote\t/tmp/remote.git\nbranch\tmain\n",
		"blank profile": "git-remote\t/tmp/remote.git\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repo\thttps://localhost:8443\tus-east-1\t\tr\t-\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestConfigFileCannotBeSymlinkOrWritableByOthers(t *testing.T) {
	directory := t.TempDir()
	real := filepath.Join(directory, "real")
	data := "git-remote\t/tmp/remote.git\nbranch\tmain\nmirror\tlocal\tbackup-server\ts3://backup-test/repo\thttps://localhost:8443\tus-east-1\tw\tr\t-\n"
	if err := os.WriteFile(real, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(real); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("unsafe mode accepted: %v", err)
	}
	if err := os.Chmod(real, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink config accepted")
	}
}
