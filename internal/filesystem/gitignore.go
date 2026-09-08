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
	command   *exec.Cmd
	input     io.WriteCloser
	output    *bufio.Reader
	base      string
	stderr    *gitIgnoreDiagnostic
	workspace string
	parent    *gitIgnore
	fallback  bool
}

type gitIgnoreDiagnostic struct {
	data     []byte
	overflow bool
}

func (diagnostic *gitIgnoreDiagnostic) Write(data []byte) (int, error) {
	count := min(len(data), (4<<10)-len(diagnostic.data))
	diagnostic.data = append(diagnostic.data, data[:count]...)
	diagnostic.overflow = diagnostic.overflow || count < len(data)
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
			err = checkInheritedGitIgnores(parent, path)
			if err == nil {
				ignore, err = startGitIgnore(fd, parent)
			}
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

func startGitIgnore(directoryFD int, path string) (_ *gitIgnore, returnErr error) {
	defer func() {
		if returnErr != nil {
			returnErr = fmt.Errorf("source Git ignore setup in %q: %w", path, returnErr)
		}
	}()
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer func() { _ = dir.Close() }()
	metadata, err := sourceGitMetadata(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect source Git metadata in %q: %w", path, err)
	}
	gitDirectory := ".git"
	valid := false
	if metadata != "" {
		_, code, err := sourceGitOutput(dir, "", "rev-parse", "--resolve-git-dir", ".git")
		if err != nil && code != 128 {
			return nil, err
		}
		valid = code == 0
	}
	ignore := &gitIgnore{base: path}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, ignore.close())
		}
	}()
	if !valid {
		ignore.workspace, err = makeIgnoreWorkspace()
		if err != nil {
			return nil, err
		}
		gitDirectory = ignore.workspace
		ignore.fallback, err = hasGitMarker(directoryFD, path)
		if err != nil {
			return nil, err
		}
		if metadata != "" {
			output, err := os.OpenFile(filepath.Join(ignore.workspace, "info", "exclude"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return nil, err
			}
			copyErr := copyIgnoreFile(metadata+"/info/exclude", output, maxGitIgnoreFileBytes)
			if err := errors.Join(copyErr, output.Close()); err != nil {
				return nil, err
			}
		}
	} else {
		exclude, _, err := sourceGitOutput(dir, gitDirectory, "rev-parse", "--path-format=absolute", "--git-path", "info/exclude")
		if err != nil {
			return nil, err
		}
		if err := copyIgnoreFile(exclude, io.Discard, maxGitIgnoreFileBytes); err != nil {
			return nil, err
		}
	}
	if err := checkGlobalIgnore(dir, gitDirectory); err != nil {
		return nil, err
	}
	command := sourceGitCommand(dir, gitDirectory, "check-ignore", "--stdin", "-z", "--verbose", "--non-matching")
	if !valid {
		command.Args = append(command.Args, "--no-index")
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
	ignore.command, ignore.input, ignore.output, ignore.stderr = command, input, bufio.NewReaderSize(output, 64<<10), stderr
	// Probe even an empty worktree. Ordinary Git/configuration errors are fatal,
	// not a reason to retry with different exclusion semantics.
	if _, err := ignore.match(path, false); err != nil {
		return nil, err
	}
	return ignore, nil
}

func (ignore *gitIgnore) close() error {
	if ignore == nil {
		return nil
	}
	if ignore.command != nil {
		_ = ignore.input.Close()
		_ = ignore.command.Process.Kill()
		_ = ignore.command.Wait()
		ignore.command = nil
	}
	if ignore.workspace != "" {
		if err := os.RemoveAll(ignore.workspace); err != nil {
			return err
		}
		ignore.workspace = ""
	}
	return nil
}

func (ignore *gitIgnore) ownsWorkspace(path string) bool {
	for current := ignore; current != nil; current = current.parent {
		if path == current.workspace {
			return true
		}
	}
	return false
}

func (ignore *gitIgnore) failure(err error) error {
	closeErr := ignore.close() // Wait joins the bounded stderr writer before reading it.
	return errors.Join(fmt.Errorf("source Git ignore check in %q: %w: %s", ignore.base, err, strings.TrimSpace(string(ignore.stderr.data))), closeErr)
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
