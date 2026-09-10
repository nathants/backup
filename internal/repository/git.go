package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"backup/internal/format"
)

const (
	maximumGitErrorBytes = 64 << 10
	maximumCommitCount   = 10_000_000
)

type ValidatedCommit struct {
	CommitID   string
	ParentID   string
	State      State
	BlobIDs    map[string]string
	Transition TransitionKind
}

type Validator struct {
	Repo      string
	Limits    format.Limits
	CachePath string
}

func (validator Validator) validateCommit(commitID string) (ValidatedCommit, error) {
	objectType, err := validator.gitOutput(128, "cat-file", "-t", commitID)
	if err != nil {
		return ValidatedCommit{}, err
	}
	if strings.TrimSpace(string(objectType)) != "commit" {
		return ValidatedCommit{}, fmt.Errorf("object is not a commit")
	}
	parentLine, err := validator.gitOutput(1024, "rev-list", "--parents", "--max-count=1", commitID)
	if err != nil {
		return ValidatedCommit{}, err
	}
	parts := strings.Fields(string(parentLine))
	if len(parts) < 1 || parts[0] != commitID {
		return ValidatedCommit{}, fmt.Errorf("could not inspect commit parents")
	}
	if len(parts) > 2 {
		return ValidatedCommit{}, fmt.Errorf("commit has %d parents, expected one", len(parts)-1)
	}
	parentID := ""
	if len(parts) == 2 {
		if !isGitOID(parts[1]) {
			return ValidatedCommit{}, fmt.Errorf("commit has invalid parent ID")
		}
		parentID = parts[1]
	}
	treeData, err := validator.gitOutput(8<<20, "ls-tree", "-z", "--full-tree", commitID)
	if err != nil {
		return ValidatedCommit{}, err
	}
	entries, err := parseRootTree(treeData)
	if err != nil {
		return ValidatedCommit{}, err
	}
	if len(entries) != len(RequiredBlobNames) {
		return ValidatedCommit{}, fmt.Errorf("tree has %d root entries, expected exactly %d", len(entries), len(RequiredBlobNames))
	}
	gitBlobs := make(map[string]gitBlob, len(entries))
	blobIDs := make(map[string]string, len(entries))
	for _, name := range RequiredBlobNames {
		entry, ok := entries[name]
		if !ok {
			return ValidatedCommit{}, fmt.Errorf("tree is missing required blob %q", name)
		}
		if entry.mode != "100644" || entry.objectType != "blob" {
			return ValidatedCommit{}, fmt.Errorf("tree entry %q has mode/type %s %s, expected 100644 blob", name, entry.mode, entry.objectType)
		}
		declared, err := validator.blobSize(entry.objectID)
		if err != nil {
			return ValidatedCommit{}, fmt.Errorf("inspect blob %q: %w", name, err)
		}
		maximum := validator.maximumBlobSize(name)
		if declared > maximum {
			return ValidatedCommit{}, fmt.Errorf("blob %q declared size %d exceeds %d", name, declared, maximum)
		}
		gitBlobs[name] = gitBlob{objectID: entry.objectID, size: declared}
		blobIDs[name] = entry.objectID
	}
	state, err := parseStreamState(gitStateSource{validator: validator, blobs: gitBlobs}, validator.effectiveLimits(), false)
	if err != nil {
		return ValidatedCommit{}, err
	}
	return ValidatedCommit{CommitID: commitID, ParentID: parentID, State: state, BlobIDs: blobIDs}, nil
}

type treeEntry struct {
	mode       string
	objectType string
	objectID   string
}

type gitBlob struct {
	objectID string
	size     int64
}

type gitStateSource struct {
	validator Validator
	blobs     map[string]gitBlob
}

func (source gitStateSource) withBlob(name string, visit func(io.Reader) error) error {
	blob, ok := source.blobs[name]
	if !ok {
		return fmt.Errorf("metadata source lacks blob %q", name)
	}
	return source.validator.withGitBlob(blob.objectID, blob.size, visit)
}

func parseRootTree(data []byte) (map[string]treeEntry, error) {
	entries := make(map[string]treeEntry)
	if len(data) == 0 || data[len(data)-1] != 0 {
		return nil, fmt.Errorf("git tree listing is empty or not NUL-terminated")
	}
	for _, record := range bytes.Split(data[:len(data)-1], []byte{0}) {
		tab := bytes.IndexByte(record, '\t')
		if tab <= 0 || tab == len(record)-1 {
			return nil, fmt.Errorf("malformed Git tree record")
		}
		metadata := strings.Fields(string(record[:tab]))
		name := string(record[tab+1:])
		if len(metadata) != 3 || name == "" || strings.ContainsAny(name, "/\x00\r\n") {
			return nil, fmt.Errorf("malformed Git tree entry")
		}
		if !isGitOID(metadata[2]) {
			return nil, fmt.Errorf("tree entry %q has invalid object ID", name)
		}
		if _, exists := entries[name]; exists {
			return nil, fmt.Errorf("tree contains duplicate entry %q", name)
		}
		entries[name] = treeEntry{mode: metadata[0], objectType: metadata[1], objectID: metadata[2]}
	}
	return entries, nil
}

func (validator Validator) blobSize(objectID string) (int64, error) {
	objectType, err := validator.gitOutput(128, "cat-file", "-t", objectID)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(string(objectType)) != "blob" {
		return 0, fmt.Errorf("object %s is not a blob", objectID)
	}
	sizeText, err := validator.gitOutput(128, "cat-file", "-s", objectID)
	if err != nil {
		return 0, err
	}
	trimmed := strings.TrimSpace(string(sizeText))
	if trimmed == "" || trimmed != "0" && strings.HasPrefix(trimmed, "0") {
		return 0, fmt.Errorf("git returned noncanonical blob size %q", trimmed)
	}
	size, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("git returned invalid blob size %q", trimmed)
	}
	return size, nil
}

func (validator Validator) effectiveLimits() format.Limits {
	limits := validator.Limits
	if limits.MaxFileBytes == 0 {
		limits = format.DefaultLimits()
	}
	return limits
}

func (validator Validator) maximumBlobSize(name string) int64 {
	maximum := validator.effectiveLimits().MaxFileBytes
	var tighter int64
	switch name {
	case "FORMAT":
		tighter = 64 << 10
	case ".publickeys":
		tighter = format.MaximumPublicKeysBytes
	case "mirrors.tsv":
		tighter = format.MaximumMirrorsBytes
	case "ignore":
		tighter = format.MaximumIgnoreBytes
	default:
		return maximum
	}
	if tighter < maximum {
		return tighter
	}
	return maximum
}

func isGitOID(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, char := range []byte(value) {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

// Check once and keep using that executable path: querying config values alone
// cannot detect an older Git silently ignoring an unknown durability setting.
var durableGitExecutable = sync.OnceValues(findDurableGit)

var gitVersionPattern = regexp.MustCompile(`^git version ([0-9]+)\.([0-9]+)\.[0-9]+[^\r\n]*\n?$`)

func findDurableGit() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("locate Git: %w", err)
	}
	command := exec.Command(path, "--version")
	command.Env = sanitizedGitEnvironment()
	stdout := &boundedBuffer{limit: 1024}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("check Git durability support: %w: %s", err, strings.TrimSpace(stderr.buffer.String()))
	}
	if stdout.exceeded || stderr.exceeded || stderr.buffer.Len() != 0 {
		return "", fmt.Errorf("check Git durability support: excessive output or unexpected diagnostic")
	}
	version := gitVersionPattern.FindStringSubmatch(stdout.buffer.String())
	if version == nil {
		return "", fmt.Errorf("check Git durability support: unrecognized version %q", stdout.buffer.String())
	}
	major, majorErr := strconv.Atoi(version[1])
	minor, minorErr := strconv.Atoi(version[2])
	if majorErr != nil || minorErr != nil || major < 2 || major == 2 && minor < 36 {
		return "", fmt.Errorf("durable metadata requires Git 2.36 or newer for core.fsync=objects,reference and core.fsyncMethod=fsync (found %q)", strings.TrimSpace(version[0]))
	}
	return path, nil
}

func hardenedGitCommand(repositoryPath string, arguments ...string) (*exec.Cmd, error) {
	path, err := durableGitExecutable()
	if err != nil {
		return nil, err
	}
	args := []string{
		"--no-pager", "--literal-pathspecs", "--no-replace-objects",
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.autocrlf=false",
		"-c", "core.eol=lf",
		"-c", "core.fsync=objects,reference",
		"-c", "core.fsyncMethod=fsync",
	}
	if repositoryPath != "" {
		args = append(args, "-C", repositoryPath)
	}
	args = append(args, arguments...)
	command := exec.Command(path, args...)
	command.Env = sanitizedGitEnvironment()
	return command, nil
}

func runStandaloneGit(limit int64, arguments ...string) ([]byte, error) {
	if limit < 1 || len(arguments) == 0 {
		return nil, fmt.Errorf("invalid Git command")
	}
	command, err := hardenedGitCommand("", arguments...)
	if err != nil {
		return nil, err
	}
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Run()
	if stdout.exceeded {
		return nil, fmt.Errorf("git %s output exceeded %d bytes", arguments[0], limit)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &GitExitError{Operation: arguments[0], ExitCode: exitErr.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return nil, fmt.Errorf("start git %s: %w", arguments[0], err)
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

// ValidateBranch checks Git's complete branch syntax before callers persist a
// destination pin or mutate repository setup. Checkout expressions must not be
// expanded into a different branch, even when the current directory has a reflog.
func ValidateBranch(branch string) error {
	output, err := runStandaloneGit(maximumGitErrorBytes, "check-ref-format", "--branch", branch)
	if err != nil {
		return fmt.Errorf("invalid metadata branch %q: %w", branch, err)
	}
	if string(output) != branch+"\n" {
		return fmt.Errorf("invalid metadata branch %q: expected a literal branch name", branch)
	}
	return nil
}

// InitializeBareSHA256 creates a bare SHA-256 repository through the same
// hardened, bounded Git runner used by every other production invocation.
func InitializeBareSHA256(directory string) error {
	if directory == "" {
		return fmt.Errorf("bare repository path is required")
	}
	_, err := runStandaloneGit(64<<10, "init", "--bare", "--object-format=sha256", directory)
	return err
}

func (validator Validator) withGitBlob(objectID string, declared int64, visit func(io.Reader) error) error {
	if !isGitOID(objectID) || declared < 0 || visit == nil {
		return fmt.Errorf("invalid Git blob stream request")
	}
	command, err := hardenedGitCommand(validator.Repo, "cat-file", "blob", objectID)
	if err != nil {
		return err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start git cat-file: %w", err)
	}
	tracked := &countingReader{reader: io.LimitReader(stdout, declared)}
	visitErr := visit(tracked)
	if visitErr == nil {
		_, visitErr = io.Copy(io.Discard, tracked)
	}
	var extra [1]byte
	extraCount := 0
	if visitErr == nil {
		extraCount, err = stdout.Read(extra[:])
		if err != nil && !errors.Is(err, io.EOF) {
			visitErr = err
		}
	}
	if visitErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return visitErr
	}
	waitErr := command.Wait()
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return &GitExitError{Operation: "cat-file", ExitCode: exitErr.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return fmt.Errorf("wait for git cat-file: %w", waitErr)
	}
	if tracked.count != uint64(declared) || extraCount != 0 {
		return fmt.Errorf("git blob %s returned a size different from its declaration", objectID)
	}
	return nil
}

func (validator Validator) gitOutput(limit int64, arguments ...string) ([]byte, error) {
	if limit < 1 {
		return nil, fmt.Errorf("invalid Git output limit")
	}
	command, err := hardenedGitCommand(validator.Repo, arguments...)
	if err != nil {
		return nil, err
	}
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	if stdout.exceeded {
		return nil, fmt.Errorf("git %s output exceeded %d bytes", arguments[0], limit)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &GitExitError{Operation: arguments[0], ExitCode: exitErr.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return nil, fmt.Errorf("start git %s: %w", arguments[0], err)
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

type GitExitError struct {
	Operation string
	ExitCode  int
	Detail    string
}

func (err *GitExitError) Error() string {
	if err.Detail == "" {
		return fmt.Sprintf("git %s exited with status %d", err.Operation, err.ExitCode)
	}
	return fmt.Sprintf("git %s exited with status %d: %s", err.Operation, err.ExitCode, err.Detail)
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - int64(buffer.buffer.Len())
	if remaining <= 0 {
		buffer.exceeded = true
		return len(data), nil
	}
	toWrite := data
	if int64(len(toWrite)) > remaining {
		toWrite = toWrite[:remaining]
		buffer.exceeded = true
	}
	_, _ = buffer.buffer.Write(toWrite)
	return len(data), nil
}

func sanitizedGitEnvironment() []string {
	allowedExact := map[string]bool{
		"HOME": true, "PATH": true, "TMPDIR": true, "SSH_AUTH_SOCK": true,
		"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
		"AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true, "AWS_SHARED_CREDENTIALS_FILE": true, "AWS_CONFIG_FILE": true,
		"AWS_CA_BUNDLE": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
		"GIT_REMOTE_AWS_PUBLICKEY": true, "GIT_REMOTE_AWS_SECRETKEY": true, "GIT_REMOTE_AWS_SECRETKEY_FILE": true, "GIT_REMOTE_AWS_SECRETKEY_CMD": true,
	}
	result := []string{"LC_ALL=C", "LANG=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0"}
	for _, item := range os.Environ() {
		name, _, ok := strings.Cut(item, "=")
		if ok && allowedExact[name] {
			result = append(result, item)
		}
	}
	return result
}

func AtomicWriteMetadata(directory string, blobs map[string][]byte) error {
	if len(blobs) != len(RequiredBlobNames) {
		return fmt.Errorf("metadata materialization requires exactly seven blobs")
	}
	for _, name := range RequiredBlobNames {
		data, ok := blobs[name]
		if !ok {
			return fmt.Errorf("missing metadata blob %q", name)
		}
		if err := atomicWriteFile(filepath.Join(directory, name), data, 0o644); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".backup-metadata-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	published := false
	defer func() {
		_ = file.Close()
		if !published {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	published = true
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

var _ io.Writer = (*boundedBuffer)(nil)
