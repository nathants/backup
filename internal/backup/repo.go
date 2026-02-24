package backup

import (
	"fmt"
	"os"
	"path/filepath"
)

func ensureRepoInitialized(config Config) error {
	backupDir := config.BackupDir()
	if _, err := os.Stat(filepath.Join(backupDir, ".git")); err == nil {
		return nil
	}
	return fmt.Errorf("backup repo not initialized; run backup init")
}

func ensureRepoCloned(config Config) error {
	backupDir := config.BackupDir()
	if _, err := os.Stat(filepath.Join(backupDir, ".git")); err == nil {
		return nil
	}
	return gitClone(config.GitRemote, backupDir)
}
