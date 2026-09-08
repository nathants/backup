package filesystem

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// One streaming Git process per active worktree keeps the index and ignore
// matcher in Git, without a process per path or an in-memory path catalog.
// Unlike metadata Git commands, this intentionally honors user ignore config.
type gitIgnore struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Reader
	base    string
	stderr  *gitIgnoreDiagnostic
}

type gitIgnoreDiagnostic struct{ data []byte }

func (diagnostic *gitIgnoreDiagnostic) Write(data []byte) (int, error) {
	count := min(len(data), (4<<10)-len(diagnostic.data))
	diagnostic.data = append(diagnostic.data, data[:count]...)
	return len(data), nil
}

func gitMetadataPath(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component == ".git" {
			return true
		}
	}
	return false
}

func hasGitMarker(directoryFD int, path string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(directoryFD, ".git", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR && stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, fmt.Errorf("source .git must be a directory or regular gitfile: %q", path)
	}
	return true, nil
}

func inheritedGitIgnore(directoryFD int, path string) (*gitIgnore, error) {
	if gitMetadataPath(path) {
		return nil, nil
	}
	found, err := hasGitMarker(directoryFD, path)
	if found || err != nil {
		return nil, err // scanDirectory opens this root's own matcher.
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		found, err := hasGitMarker(fd, parent)
		var ignore *gitIgnore
		if found && err == nil {
			ignore, err = startGitIgnore(fd, parent)
		}
		_ = unix.Close(fd)
		if found || err != nil {
			return ignore, err
		}
		if parent == filepath.Dir(parent) {
			return nil, nil
		}
	}
}

func startGitIgnore(directoryFD int, path string) (*gitIgnore, error) {
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer func() { _ = dir.Close() }()
	command := exec.Command("git", "--no-pager", "--no-replace-objects",
		"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
		"-c", "core.untrackedCache=false", "-c", "core.attributesFile=/dev/null",
		"-c", "core.fsync=objects,reference", "-c", "core.fsyncMethod=fsync",
		"-C", "/proc/self/fd/3", "--git-dir=.git", "--work-tree=.",
		"check-ignore", "--stdin", "-z", "--verbose", "--non-matching")
	command.ExtraFiles = []*os.File{dir}
	command.Env = []string{"LC_ALL=C", "LANG=C", "GIT_FLUSH=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="}
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		switch name {
		case "HOME", "PATH", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM":
			command.Env = append(command.Env, item)
		}
	}
	stderr := &gitIgnoreDiagnostic{}
	command.Stderr = stderr
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	ignore := &gitIgnore{command: command, input: input, output: bufio.NewReaderSize(output, 64<<10), base: path, stderr: stderr}
	// Probe even an empty worktree so corrupt Git metadata never silently
	// disables ignore handling simply because no source paths are visited.
	if _, err := ignore.match(path, false); err != nil {
		ignore.close()
		return nil, err
	}
	return ignore, nil
}

func (ignore *gitIgnore) close() {
	if ignore == nil || ignore.command == nil {
		return
	}
	// The stream was checked response-by-response. Termination avoids waiting on
	// a damaged or stuck child during cleanup, including after a protocol error.
	_ = ignore.input.Close()
	_ = ignore.command.Process.Kill()
	_ = ignore.command.Wait()
	ignore.command = nil
}

func (ignore *gitIgnore) failure(err error) error {
	ignore.close() // Wait joins the bounded stderr writer before reading it.
	return fmt.Errorf("source Git ignore check in %q: %w: %s", ignore.base, err, strings.TrimSpace(string(ignore.stderr.data)))
}

func (ignore *gitIgnore) match(path string, directory bool) (bool, error) {
	if ignore == nil || gitMetadataPath(path) {
		return false, nil
	}
	relative, err := filepath.Rel(ignore.base, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
		return false, fmt.Errorf("path is outside source Git worktree")
	}
	// check-ignore rejects --literal-pathspecs. Its stdin paths are not globs;
	// the ./ prefix also prevents a leading colon from becoming pathspec magic.
	relative = "./" + relative
	if directory {
		relative += "/"
	}
	if _, err := io.WriteString(ignore.input, relative+"\x00"); err != nil {
		return false, ignore.failure(err)
	}
	var fields [4]string
	for i := range fields {
		field, err := ignore.output.ReadSlice(0)
		if err != nil {
			return false, ignore.failure(err)
		}
		fields[i] = string(bytes.TrimSuffix(field, []byte{0}))
	}
	if fields[3] != relative {
		return false, fmt.Errorf("git ignore result does not match source path %q", path)
	}
	return fields[2] != "" && !strings.HasPrefix(fields[2], "!"), nil
}
