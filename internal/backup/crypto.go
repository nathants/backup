package backup

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/nathants/go-libsodium"
)

var initOnce sync.Once

func InitCrypto() {
	initOnce.Do(func() {
		libsodium.Init()
	})
}

func LoadPublicKeys(path string) ([][]byte, error) {
	InitCrypto()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	lines := bytes.Split(data, []byte("\n"))
	pk, _, err := libsodium.BoxKeypair()
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		decoded, err := hex.DecodeString(string(bytes.TrimSpace(line)))
		if err != nil {
			return nil, err
		}
		if len(decoded) != len(pk) {
			return nil, fmt.Errorf("malformed .publickeys line length %d", len(decoded))
		}
		keys = append(keys, decoded)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf(".publickeys is empty")
	}
	return keys, nil
}

func LoadSecretKey() ([]byte, error) {
	InitCrypto()
	env := strings.TrimSpace(os.Getenv("GIT_REMOTE_AWS_SECRETKEY"))
	if env != "" {
		decoded, err := hex.DecodeString(env)
		if err != nil {
			return nil, fmt.Errorf("GIT_REMOTE_AWS_SECRETKEY is not hex: %w", err)
		}
		return decoded, nil
	}
	cmdEnv := strings.TrimSpace(os.Getenv("GIT_REMOTE_AWS_SECRETKEY_CMD"))
	if cmdEnv != "" {
		cmd := exec.Command(cmdEnv)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("GIT_REMOTE_AWS_SECRETKEY_CMD failed: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		decoded, err := hex.DecodeString(strings.TrimSpace(stdout.String()))
		if err != nil {
			return nil, fmt.Errorf("GIT_REMOTE_AWS_SECRETKEY_CMD output is not hex: %w", err)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("GIT_REMOTE_AWS_SECRETKEY or GIT_REMOTE_AWS_SECRETKEY_CMD must be set")
}
