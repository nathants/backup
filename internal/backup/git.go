package backup

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func runGit(repoDir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func runGitRaw(repoDir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func gitInit(repoDir string) error {
	_, err := runGit(repoDir, "init")
	return err
}

func gitAdd(repoDir string, paths ...string) error {
	args := append([]string{"add"}, paths...)
	_, err := runGit(repoDir, args...)
	return err
}

func gitCommit(repoDir string, messages []string) error {
	if len(messages) == 0 {
		return fmt.Errorf("commit message required")
	}
	args := []string{"commit"}
	for _, message := range messages {
		args = append(args, "-m", message)
	}
	_, err := runGit(repoDir, args...)
	return err
}

func gitPush(repoDir string) error {
	_, err := runGit(repoDir, "push", "origin", "HEAD")
	return err
}

func gitClone(remote string, repoDir string) error {
	cmd := exec.Command("git", "clone", remote, repoDir)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("git clone failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func gitHasHead(repoDir string) bool {
	_, err := runGit(repoDir, "rev-parse", "--verify", "HEAD")
	return err == nil
}

func gitListFiles(repoDir string) ([]string, error) {
	output, err := runGit(repoDir, "ls-files")
	if err != nil {
		return nil, err
	}
	if output == "" {
		return nil, nil
	}
	return strings.Split(output, "\n"), nil
}

func gitRevCount(repoDir string) (int, error) {
	output, err := runGit(repoDir, "rev-list", "--count", "HEAD")
	if err != nil {
		if strings.Contains(err.Error(), "fatal") {
			return 0, nil
		}
		return 0, err
	}
	count, err := parseInt(output)
	if err != nil {
		return 0, err
	}
	return count, nil
}
