package filesystem

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxGitIgnoreFileBytes = 16 << 20

func sourceGitCommand(directory *os.File, gitDirectory string, arguments ...string) *exec.Cmd {
	args := []string{"--no-pager", "--no-replace-objects",
		"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
		"-c", "core.untrackedCache=false", "-c", "core.attributesFile=/dev/null",
		"-c", "core.fsync=objects,reference", "-c", "core.fsyncMethod=fsync",
		"-C", "/proc/self/fd/3"}
	if gitDirectory != "" {
		args = append(args, "--git-dir="+gitDirectory, "--work-tree=.")
	}
	command := exec.Command("git", append(args, arguments...)...)
	command.ExtraFiles = []*os.File{directory}
	command.Env = []string{"LC_ALL=C", "LANG=C", "GIT_FLUSH=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="}
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		switch name {
		case "HOME", "PATH", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM":
			command.Env = append(command.Env, item)
		}
	}
	return command
}

func sourceGitOutput(directory *os.File, gitDirectory string, arguments ...string) (string, int, error) {
	command := sourceGitCommand(directory, gitDirectory, arguments...)
	var stdout, stderr gitIgnoreDiagnostic
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return "", -1, fmt.Errorf("source Git diagnostic exceeds size limit")
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return "", -1, err
	}
	code := 0
	if exit != nil {
		code = exit.ExitCode()
	}
	if code != 0 {
		return "", code, fmt.Errorf("source Git exited %d: %s", code, strings.TrimSpace(string(stderr.data)))
	}
	return strings.TrimSuffix(string(stdout.data), "\n"), 0, nil
}

func descriptorPath(directory *os.File, name string) string {
	// Preserve .. after the descriptor: lexical cleaning would escape /proc/self/fd/N.
	return "/proc/self/fd/" + strconv.FormatUint(uint64(directory.Fd()), 10) + "/" + name
}

// Git's repository recognizer conflates missing metadata and access failures.
// Check readable metadata first so only structural invalidity permits fallback.
func sourceGitMetadata(directory *os.File) (string, error) {
	marker := descriptorPath(directory, ".git")
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode().IsRegular() {
		var text bytes.Buffer
		if err := copyIgnoreFile(marker, &text, 64<<10); err != nil {
			return "", err
		}
		value := strings.TrimRight(text.String(), "\r\n")
		if !strings.HasPrefix(value, "gitdir: ") || strings.ContainsAny(value, "\x00\r\n") {
			return "", nil
		}
		marker = strings.TrimPrefix(value, "gitdir: ")
		if marker == "" {
			return "", nil
		}
		if !filepath.IsAbs(marker) {
			marker = descriptorPath(directory, marker)
		}
	} else if !info.IsDir() {
		return "", fmt.Errorf("source .git must be a directory or regular gitfile")
	}
	if err := checkGitDirectoryReadable(marker); err != nil {
		return "", err
	}
	var common bytes.Buffer
	if err := copyIgnoreFile(marker+"/commondir", &common, 64<<10); err != nil {
		return "", err
	}
	if value := strings.TrimRight(common.String(), "\r\n"); value != "" && !strings.ContainsAny(value, "\x00\r\n") {
		if filepath.IsAbs(value) {
			marker = value
		} else {
			marker += "/" + value
		}
		if err := checkGitDirectoryReadable(marker); err != nil {
			return "", err
		}
	}
	return marker, nil
}

func checkGitDirectoryReadable(path string) error {
	for _, name := range []string{"", "objects", "refs"} {
		fd, err := unix.Open(path+"/"+name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			continue
		}
		if err != nil {
			return err
		}
		err = unix.Faccessat(fd, ".", unix.R_OK|unix.X_OK, unix.AT_EACCESS)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	return copyIgnoreFile(path+"/HEAD", io.Discard, 64<<10)
}

// A private minimal repository gives native check-ignore a metadata context
// without consulting an incomplete source repository or writing into the source.
func makeIgnoreWorkspace() (string, error) {
	path, err := os.MkdirTemp("", "backup-git-ignore-")
	if err != nil {
		return "", err
	}
	absolute, err := filepath.EvalSymlinks(path)
	if err == nil {
		absolute, err = filepath.Abs(absolute)
	}
	if err == nil {
		for _, name := range []string{"objects", "refs", "info"} {
			if err = os.Mkdir(filepath.Join(absolute, name), 0700); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(absolute, "HEAD"), []byte("ref: refs/heads/ignore\n"), 0600)
	}
	if err != nil {
		return "", errors.Join(err, os.RemoveAll(path))
	}
	return absolute, nil
}

// Missing files have no rules. Present files must be readable and bounded;
// native Git can otherwise warn and continue without applying their exclusions.
func copyIgnoreFile(path string, destination io.Writer, limit int64) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Git ignore metadata %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return fmt.Errorf("git ignore metadata %q must be a regular file of at most %d bytes", path, limit)
	}
	n, err := io.Copy(destination, io.LimitReader(file, limit+1))
	if err != nil {
		return fmt.Errorf("read Git ignore metadata %q: %w", path, err)
	}
	if n > limit {
		return fmt.Errorf("git ignore metadata %q exceeds %d bytes", path, limit)
	}
	return nil
}

func checkDirectoryIgnore(directoryFD int) error {
	// Git deliberately does not follow a symlink used as a .gitignore file.
	var info unix.Stat_t
	if err := unix.Fstatat(directoryFD, ".gitignore", &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if info.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil
	}
	return copyIgnoreFile(filepath.Join("/proc/self/fd", strconv.Itoa(directoryFD), ".gitignore"), io.Discard, maxGitIgnoreFileBytes)
}

func checkGlobalIgnore(directory *os.File, gitDirectory string) error {
	path, code, err := sourceGitOutput(directory, gitDirectory, "config", "--path", "--get", "core.excludesFile")
	if err != nil && code != 1 {
		return err
	}
	if code == 1 {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(os.Getenv("HOME"), ".config")
		}
		path = filepath.Join(base, "git", "ignore")
	}
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		path = descriptorPath(directory, path)
	}
	return copyIgnoreFile(path, io.Discard, maxGitIgnoreFileBytes)
}

func checkInheritedGitIgnores(base, root string) error {
	for path := root; ; path = filepath.Dir(path) {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = checkDirectoryIgnore(fd)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
		if path == base {
			return nil
		}
		if path == filepath.Dir(path) {
			return fmt.Errorf("source Git ignore root is not beneath its base")
		}
	}
}
