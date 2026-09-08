package repository

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const stateDirectoryName = ".backup-state"

type Managed struct {
	Directory                   string
	Remote                      string
	Branch                      string
	ValidationCache             string
	MaterializationFailurePoint func(string) error
}

type WorktreeStatus struct {
	Clean bool
	Paths []string
}

func Initialize(directory, remote, branch string) (*Managed, error) {
	if directory == "" || remote == "" || branch == "" || strings.HasPrefix(branch, "-") || strings.ContainsAny(branch, "\x00\r\n") {
		return nil, fmt.Errorf("metadata directory, remote, and branch are required")
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("metadata path already exists and is not a directory")
		}
		entries, readErr := os.ReadDir(directory)
		if readErr != nil {
			return nil, readErr
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf("metadata directory already exists and is not empty")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open metadata directory without following symlinks: %w", err)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Close(fd); err != nil {
		return nil, err
	}
	if _, err := runStandaloneGit(64<<10, "init", "--object-format=sha256", "--initial-branch="+branch, directory); err != nil {
		return nil, fmt.Errorf("initialize Git SHA-256 repository: %w", err)
	}
	repo := &Managed{Directory: directory, Remote: remote, Branch: branch}
	settings := [][]string{
		{"config", "core.hooksPath", "/dev/null"},
		{"config", "core.autocrlf", "false"},
		{"config", "core.filemode", "true"},
		{"config", "core.symlinks", "true"},
		{"config", "advice.detachedHead", "false"},
		{"config", "status.showUntrackedFiles", "no"},
		{"remote", "add", "origin", remote},
	}
	for _, arguments := range settings {
		if _, err := repo.run(nil, 64<<10, arguments...); err != nil {
			return nil, err
		}
	}
	excludePath := filepath.Join(directory, ".git", "info", "exclude")
	if err := atomicWriteFile(excludePath, []byte("/"+stateDirectoryName+"/\n"), 0o600); err != nil {
		return nil, err
	}
	return repo, nil
}

func OpenManaged(directory, remote, branch string) (*Managed, error) {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open metadata directory without following symlinks: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return nil, err
	}
	repo := &Managed{Directory: directory, Remote: remote, Branch: branch}
	objectFormat, err := repo.run(nil, 1024, "rev-parse", "--show-object-format")
	if err != nil || strings.TrimSpace(string(objectFormat)) != "sha256" {
		return nil, fmt.Errorf("metadata repository is not Git SHA-256")
	}
	configured, err := repo.run(nil, 64<<10, "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(configured)) != remote {
		return nil, fmt.Errorf("metadata Git remote does not match its trusted pin")
	}
	return repo, nil
}

func (repo *Managed) CreateCommit(base string, blobs map[string][]byte, message string) (string, error) {
	candidate, err := ParseState(blobs, format.DefaultLimits())
	if err != nil {
		return "", err
	}
	return repo.CreateCommitState(base, candidate, message)
}

// CreateCommitState creates a commit from a validated state while streaming
// every metadata blob to Git. Large catalogs are never assembled in memory.
func (repo *Managed) CreateCommitState(base string, candidate State, message string) (string, error) {
	if message == "" || strings.ContainsRune(message, 0) {
		return "", fmt.Errorf("commit message is required")
	}
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	if base == "" {
		if err := candidate.ValidateGenesis(); err != nil {
			return "", err
		}
	} else {
		history, err := (Validator{Repo: repo.Directory, Limits: format.DefaultLimits(), CachePath: repo.ValidationCache}).ValidateHistory(base)
		if err != nil {
			return "", err
		}
		defer func() { _ = history.Close() }()
		tip, err := history.Tip()
		if err != nil {
			return "", err
		}
		if _, err := ValidateTransition(tip.State, candidate); err != nil {
			return "", err
		}
	}
	oids := make(map[string]string, len(RequiredBlobNames))
	for _, name := range RequiredBlobNames {
		var output []byte
		err := candidate.withBlob(name, func(reader io.Reader) error {
			var err error
			output, err = repo.runReader(reader, 1024, false, "hash-object", "-w", "--stdin")
			return err
		})
		if err != nil {
			return "", err
		}
		oid := strings.TrimSpace(string(output))
		if !isGitOID(oid) {
			return "", fmt.Errorf("git hash-object returned invalid object ID")
		}
		oids[name] = oid
	}
	names := append([]string(nil), RequiredBlobNames...)
	sort.Strings(names)
	var treeInput bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&treeInput, "100644 blob %s\t%s%c", oids[name], name, byte(0))
	}
	treeOutput, err := repo.run(treeInput.Bytes(), 1024, "mktree", "-z")
	if err != nil {
		return "", err
	}
	tree := strings.TrimSpace(string(treeOutput))
	if !isGitOID(tree) {
		return "", fmt.Errorf("git mktree returned invalid object ID")
	}
	arguments := []string{"commit-tree", tree}
	if base != "" {
		arguments = append(arguments, "-p", base)
	}
	commitOutput, err := repo.runWithIdentity([]byte(message+"\n"), 1024, arguments...)
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(commitOutput))
	if !isGitOID(commit) {
		return "", fmt.Errorf("git commit-tree returned invalid object ID")
	}
	if _, err := repo.run(nil, 1024, "update-ref", "refs/backup/candidate", commit); err != nil {
		return "", err
	}
	validated, err := (Validator{Repo: repo.Directory, Limits: format.DefaultLimits()}).validateCommit(commit)
	if err != nil {
		return "", err
	}
	if validated.ParentID != base || !validated.State.Equal(candidate) {
		return "", fmt.Errorf("created commit has unexpected parent or metadata tree")
	}
	return commit, nil
}

func (repo *Managed) AcceptCommit(commit, expectedBase string) error {
	if !isGitOID(commit) || expectedBase != "" && !isGitOID(expectedBase) {
		return fmt.Errorf("invalid commit ID")
	}
	ref := "refs/heads/" + repo.Branch
	arguments := []string{"update-ref", ref, commit}
	if expectedBase == "" {
		arguments = append(arguments, strings.Repeat("0", 64))
	} else {
		arguments = append(arguments, expectedBase)
	}
	_, err := repo.run(nil, 1024, arguments...)
	return err
}

func (repo *Managed) DeleteHead(expected string) error {
	if !isGitOID(expected) {
		return fmt.Errorf("invalid expected head")
	}
	_, err := repo.run(nil, 1024, "update-ref", "-d", "refs/heads/"+repo.Branch, expected)
	return err
}

func (repo *Managed) Push(commit, expectedBase string) error {
	if !isGitOID(commit) || expectedBase != "" && !isGitOID(expectedBase) {
		return fmt.Errorf("invalid commit ID")
	}
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("resolve local metadata head before push: %w", err)
	}
	if head != commit {
		return fmt.Errorf("local metadata head %s disagrees with push commit %s", head, commit)
	}
	branchRef := "refs/heads/" + repo.Branch
	_, err = repo.run(nil, 64<<10, "push", "--porcelain", "origin", branchRef+":"+branchRef)
	if err != nil {
		return fmt.Errorf("fast-forward metadata push failed: %w", err)
	}
	return nil
}

func (repo *Managed) Fetch() error {
	_, err := repo.run(nil, 64<<10, "fetch", "--no-tags", "origin", "refs/heads/"+repo.Branch+":refs/remotes/origin/"+repo.Branch)
	return err
}

func (repo *Managed) Materialize(blobs map[string][]byte) error {
	if err := AtomicWriteMetadata(repo.Directory, blobs); err != nil {
		return err
	}
	return nil
}

// MaterializeState atomically streams a validated metadata state into the
// managed worktree one blob at a time.
func (repo *Managed) MaterializeState(state State) error {
	if repo == nil || len(state.BlobHashes) != len(RequiredBlobNames) {
		return fmt.Errorf("nil repository or incomplete validated state")
	}
	for _, name := range RequiredBlobNames {
		path := filepath.Join(repo.Directory, name)
		if err := state.withBlob(name, func(reader io.Reader) error {
			return atomicWriteReader(path, reader, 0o644)
		}); err != nil {
			return err
		}
	}
	return syncDirectory(repo.Directory)
}

const materializationIntentName = "backup-materialization-intent"

type materializationIntent struct {
	target   string
	expected string
}

func materializationValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func parseMaterializationValue(value string) (string, error) {
	if value == "-" {
		return "", nil
	}
	if !isGitOID(value) {
		return "", fmt.Errorf("invalid materialization commit ID")
	}
	return value, nil
}

func (repo *Managed) materializationIntentPath() string {
	return filepath.Join(repo.Directory, ".git", materializationIntentName)
}

func (repo *Managed) materializationCheckpoint(name string) error {
	if repo.MaterializationFailurePoint == nil {
		return nil
	}
	if err := repo.MaterializationFailurePoint(name); err != nil {
		return fmt.Errorf("failure at materialization checkpoint %s: %w", name, err)
	}
	return nil
}

// ApplyCommit durably treats the seven worktree blobs and branch ref as one
// recoverable state transition. A command can observe a mixed worktree only
// after RecoverMaterialization has completed the recorded intent.
func (repo *Managed) ApplyCommit(target, expected string) error {
	if repo == nil || repo.Branch == "" || target != "" && !isGitOID(target) || expected != "" && !isGitOID(expected) {
		return fmt.Errorf("invalid metadata materialization transition")
	}
	current, exists, err := repo.HeadIfExists()
	if err != nil {
		return err
	}
	if exists != (expected != "") || exists && current != expected {
		return fmt.Errorf("metadata branch changed before materialization")
	}
	data := []byte("target\t" + materializationValue(target) + "\nexpected\t" + materializationValue(expected) + "\n")
	if err := atomicWriteFile(repo.materializationIntentPath(), data, 0o600); err != nil {
		return fmt.Errorf("record metadata materialization intent: %w", err)
	}
	if err := repo.materializationCheckpoint("materialization-intent-recorded"); err != nil {
		return err
	}
	return repo.RecoverMaterialization()
}

func (repo *Managed) readMaterializationIntent() (materializationIntent, bool, error) {
	path := repo.materializationIntentPath()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return materializationIntent{}, false, nil
	}
	if err != nil {
		return materializationIntent{}, false, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 256 {
		return materializationIntent{}, false, fmt.Errorf("metadata materialization intent is not a bounded private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return materializationIntent{}, false, fmt.Errorf("read metadata materialization intent: %w", err)
	}
	if int64(len(data)) != info.Size() {
		return materializationIntent{}, false, fmt.Errorf("metadata materialization intent size changed while reading")
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) != 3 || lines[2] != "" || !strings.HasPrefix(lines[0], "target\t") || !strings.HasPrefix(lines[1], "expected\t") {
		return materializationIntent{}, false, fmt.Errorf("metadata materialization intent is malformed")
	}
	target, err := parseMaterializationValue(strings.TrimPrefix(lines[0], "target\t"))
	if err != nil {
		return materializationIntent{}, false, err
	}
	expected, err := parseMaterializationValue(strings.TrimPrefix(lines[1], "expected\t"))
	if err != nil {
		return materializationIntent{}, false, err
	}
	return materializationIntent{target: target, expected: expected}, true, nil
}

// RecoverMaterialization must run while the repository operation lock is held.
func (repo *Managed) RecoverMaterialization() error {
	intent, exists, err := repo.readMaterializationIntent()
	if err != nil || !exists {
		return err
	}
	current, headExists, err := repo.HeadIfExists()
	if err != nil {
		return err
	}
	currentValue := ""
	if headExists {
		currentValue = current
	}
	if currentValue != intent.expected && currentValue != intent.target {
		return fmt.Errorf("metadata branch changed during materialization recovery")
	}
	if intent.target == "" {
		for _, name := range RequiredBlobNames {
			if err := os.Remove(filepath.Join(repo.Directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := repo.materializationCheckpoint("materialization-blob-" + name); err != nil {
				return err
			}
		}
		if err := syncDirectory(repo.Directory); err != nil {
			return err
		}
	} else {
		history, err := (Validator{Repo: repo.Directory, Limits: format.DefaultLimits(), CachePath: repo.ValidationCache}).ValidateHistory(intent.target)
		if err != nil {
			return err
		}
		tip, tipErr := history.Tip()
		if tipErr == nil {
			for _, name := range RequiredBlobNames {
				path := filepath.Join(repo.Directory, name)
				tipErr = tip.State.withBlob(name, func(reader io.Reader) error { return atomicWriteReader(path, reader, 0o644) })
				if tipErr != nil {
					break
				}
				if tipErr = repo.materializationCheckpoint("materialization-blob-" + name); tipErr != nil {
					break
				}
			}
		}
		_ = history.Close()
		if tipErr != nil {
			return tipErr
		}
	}
	if currentValue != intent.target {
		if intent.target == "" {
			if err := repo.DeleteHead(intent.expected); err != nil {
				return err
			}
		} else if err := repo.AcceptCommit(intent.target, intent.expected); err != nil {
			return err
		}
	}
	if err := repo.materializationCheckpoint("materialization-ref-updated"); err != nil {
		return err
	}
	if err := os.Remove(repo.materializationIntentPath()); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Join(repo.Directory, ".git")); err != nil {
		return err
	}
	return repo.materializationCheckpoint("materialization-intent-cleared")
}

func atomicWriteReader(path string, reader io.Reader, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".backup-metadata-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	published := false
	defer func() {
		_ = file.Close()
		if !published {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := io.CopyBuffer(file, reader, make([]byte, 1<<20)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	published = true
	return syncDirectory(directory)
}

func (repo *Managed) Status() (WorktreeStatus, error) {
	if repo == nil {
		return WorktreeStatus{}, fmt.Errorf("nil managed repository")
	}
	head, err := repo.Head()
	if err != nil {
		return WorktreeStatus{}, err
	}
	history, err := (Validator{Repo: repo.Directory, Limits: format.DefaultLimits(), CachePath: repo.ValidationCache}).ValidateHistory(head)
	if err != nil {
		return WorktreeStatus{}, err
	}
	defer func() { _ = history.Close() }()
	tip, err := history.Tip()
	if err != nil {
		return WorktreeStatus{}, err
	}
	return repo.StatusAgainst(tip.State)
}

func (repo *Managed) StatusAgainst(state State) (WorktreeStatus, error) {
	if repo == nil || len(state.BlobHashes) != len(RequiredBlobNames) || len(state.BlobSizes) != len(RequiredBlobNames) {
		return WorktreeStatus{}, fmt.Errorf("nil repository or incomplete validated state")
	}
	var paths []string
	for _, name := range RequiredBlobNames {
		if err := checkStatusBlob(filepath.Join(repo.Directory, name), state.BlobSizes[name], state.BlobHashes[name]); err != nil {
			paths = append(paths, name)
		}
	}
	entries, err := os.ReadDir(repo.Directory)
	if err != nil {
		return WorktreeStatus{}, err
	}
	allowed := map[string]bool{".git": true, stateDirectoryName: true}
	for _, name := range RequiredBlobNames {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			paths = append(paths, entry.Name())
		}
	}
	sort.Strings(paths)
	return WorktreeStatus{Clean: len(paths) == 0, Paths: paths}, nil
}

func checkStatusBlob(path string, expectedSize uint64, expectedHash string) error {
	if expectedSize > uint64(^uint64(0)>>1) || expectedHash == "" {
		return fmt.Errorf("invalid expected worktree blob identity")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o644 || stat.Size < 0 || uint64(stat.Size) != expectedSize {
		return fmt.Errorf("worktree metadata blob has unexpected type, mode, or size")
	}
	hash, err := blake2b.New512(nil)
	if err != nil {
		return err
	}
	written, err := io.Copy(hash, file)
	if err != nil {
		return err
	}
	if written < 0 || uint64(written) != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return fmt.Errorf("worktree metadata blob changed while reading")
	}
	return nil
}

func (repo *Managed) Head() (string, error) {
	head, exists, err := repo.HeadIfExists()
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("metadata branch has no head")
	}
	return head, nil
}

func (repo *Managed) HeadIfExists() (string, bool, error) {
	output, err := repo.run(nil, 1024, "rev-parse", "--verify", "--quiet", "refs/heads/"+repo.Branch)
	if err != nil {
		var exit *GitExitError
		if errors.As(err, &exit) && exit.ExitCode == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	head := strings.TrimSpace(string(output))
	if !isGitOID(head) {
		return "", false, fmt.Errorf("git returned invalid branch head")
	}
	return head, true, nil
}

func (repo *Managed) WriteBundle(base, tip string, output io.Writer) error {
	if !isGitOID(tip) || base != "" && !isGitOID(base) || output == nil {
		return fmt.Errorf("invalid streaming bundle arguments")
	}
	temporaryRef := "refs/backup/bundle-tip"
	if _, err := repo.run(nil, 1024, "update-ref", temporaryRef, tip); err != nil {
		return err
	}
	defer func() { _, _ = repo.run(nil, 1024, "update-ref", "-d", temporaryRef) }()
	arguments := []string{"bundle", "create", "-", temporaryRef}
	if base != "" {
		arguments = append(arguments, "^"+base)
	}
	command := hardenedGitCommand(repo.Directory, arguments...)
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &GitExitError{Operation: "bundle", ExitCode: exit.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return fmt.Errorf("stream Git bundle: %w", err)
	}
	return nil
}

func (repo *Managed) CreateBundle(base, tip, destination string) error {
	if !isGitOID(tip) || base != "" && !isGitOID(base) {
		return fmt.Errorf("invalid bundle commit ID")
	}
	temporaryRef := "refs/backup/bundle-tip"
	if _, err := repo.run(nil, 1024, "update-ref", temporaryRef, tip); err != nil {
		return err
	}
	defer func() { _, _ = repo.run(nil, 1024, "update-ref", "-d", temporaryRef) }()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".bundle-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	arguments := []string{"bundle", "create", temporaryPath, temporaryRef}
	if base != "" {
		arguments = append(arguments, "^"+base)
	}
	if _, err := repo.run(nil, 64<<10, arguments...); err != nil {
		return err
	}
	file, err := os.OpenFile(temporaryPath, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	published = true
	return syncDirectory(filepath.Dir(destination))
}

func (repo *Managed) VerifyBundle(filename string) error {
	_, err := repo.run(nil, 64<<10, "bundle", "verify", filename)
	if err != nil {
		return fmt.Errorf("verify Git bundle: %w", err)
	}
	return nil
}

func (repo *Managed) RunGit(input []byte, limit int64, arguments ...string) ([]byte, error) {
	return repo.run(input, limit, arguments...)
}

func (repo *Managed) run(input []byte, limit int64, arguments ...string) ([]byte, error) {
	return repo.runCommand(input, limit, false, arguments...)
}

func (repo *Managed) runWithIdentity(input []byte, limit int64, arguments ...string) ([]byte, error) {
	return repo.runCommand(input, limit, true, arguments...)
}

func (repo *Managed) runCommand(input []byte, limit int64, identity bool, arguments ...string) ([]byte, error) {
	return repo.runReader(bytes.NewReader(input), limit, identity, arguments...)
}

func (repo *Managed) runReader(input io.Reader, limit int64, identity bool, arguments ...string) ([]byte, error) {
	if input == nil {
		input = bytes.NewReader(nil)
	}
	command := hardenedGitCommand(repo.Directory, arguments...)
	if identity {
		command.Env = append(command.Env, "GIT_AUTHOR_NAME=backup", "GIT_AUTHOR_EMAIL=backup@invalid", "GIT_COMMITTER_NAME=backup", "GIT_COMMITTER_EMAIL=backup@invalid")
	}
	command.Stdin = input
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, &GitExitError{Operation: arguments[0], ExitCode: exit.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return nil, err
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("git %s output exceeded %d bytes", arguments[0], limit)
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}
