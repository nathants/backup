package repository

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/securefs"
)

func (validator Validator) ValidateHistory(revision string) (_ *History, returnErr error) {
	if validator.Repo == "" {
		return nil, fmt.Errorf("repository path is required")
	}
	if revision == "" || strings.HasPrefix(revision, "-") || strings.ContainsAny(revision, "\x00\r\n") {
		return nil, fmt.Errorf("invalid revision")
	}
	objectFormat, err := validator.gitOutput(1024, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(objectFormat)) != "sha256" {
		return nil, fmt.Errorf("metadata repository must use Git SHA-256 object format")
	}
	resolved, err := validator.gitOutput(1024, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w", revision, err)
	}
	tipID := strings.TrimSpace(string(resolved))
	if !isGitOID(tipID) {
		return nil, fmt.Errorf("git returned invalid commit ID %q", tipID)
	}

	workspace, err := os.MkdirTemp("", "backup-history-validation-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = securefs.RemoveTree(workspace)
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			returnErr = errors.Join(returnErr, securefs.RemoveTree(workspace))
		}
	}()
	idsPath := filepath.Join(workspace, "commit-ids")
	ids, err := os.OpenFile(idsPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	idsOpen := true
	defer func() {
		if idsOpen {
			returnErr = errors.Join(returnErr, ids.Close())
		}
	}()
	count, err := validator.enumerateHistoryIDs(tipID, ids)
	if err != nil {
		return nil, fmt.Errorf("enumerate metadata history: %w", err)
	}
	if count == 0 {
		return nil, fmt.Errorf("metadata history is empty")
	}

	topologyRawPath := filepath.Join(workspace, "mirror-topology.raw")
	topologyRaw, err := os.OpenFile(topologyRawPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	topologyOpen := true
	defer func() {
		if topologyOpen {
			returnErr = errors.Join(returnErr, topologyRaw.Close())
		}
	}()
	appendMirrors := func(mirrors []format.Mirror) error {
		data, err := format.MarshalMirrors(mirrors)
		if err != nil {
			return err
		}
		_, err = topologyRaw.Write(data)
		return err
	}

	commitIDAt := func(index int) (string, error) {
		var record [historyRecordBytes]byte
		n, err := ids.ReadAt(record[:], int64(index)*historyRecordBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if n != len(record) || !isGitOID(string(record[:])) {
			return "", fmt.Errorf("enumerated history changed")
		}
		return string(record[:]), nil
	}

	var previousState State
	var genesisFormat format.RepositoryFormat
	var tip ValidatedCommit
	start := 0
	usedCache := false
	if cache, cacheErr := loadValidationCache(validator.CachePath); cacheErr == nil && cache.Sequence < count {
		cachedID, idErr := commitIDAt(cache.Sequence)
		if idErr == nil && cachedID == cache.CommitID {
			anchor, anchorErr := validator.validateCommit(cache.CommitID)
			if anchorErr == nil && equalBlobIDs(anchor.BlobIDs, cache.BlobIDs) {
				parentOK := cache.Sequence == 0 && anchor.ParentID == ""
				if cache.Sequence > 0 {
					previousID, previousErr := commitIDAt(cache.Sequence - 1)
					parentOK = previousErr == nil && anchor.ParentID == previousID
				}
				genesisOK := cache.Sequence != 0 || anchor.State.ValidateGenesis() == nil
				if parentOK && genesisOK {
					anchor.Transition = cache.Transition
					if err := appendMirrors(cache.Topology); err != nil {
						return nil, err
					}
					if err := appendMirrors(anchor.State.Mirrors); err != nil {
						return nil, err
					}
					start = cache.Sequence
					usedCache = true
					previousState = anchor.State
					genesisFormat = anchor.State.Format
					tip = anchor
				}
			}
		}
	}

	for index := start; index < count; index++ {
		if usedCache && index == start {
			continue
		}
		commitID, err := commitIDAt(index)
		if err != nil {
			return nil, err
		}
		commit, err := validator.validateCommit(commitID)
		if err != nil {
			return nil, fmt.Errorf("commit %s: %w", commitID, err)
		}
		if index == 0 {
			if commit.ParentID != "" {
				return nil, fmt.Errorf("genesis commit %s has a parent", commitID)
			}
			if err := commit.State.ValidateGenesis(); err != nil {
				return nil, fmt.Errorf("invalid genesis: %w", err)
			}
			genesisFormat = commit.State.Format
		} else {
			previousID, err := commitIDAt(index - 1)
			if err != nil {
				return nil, err
			}
			if commit.ParentID != previousID {
				return nil, fmt.Errorf("commit %s does not have the preceding validated commit as its sole parent", commitID)
			}
			kind, transitionErr := ValidateTransition(previousState, commit.State)
			if transitionErr != nil {
				return nil, fmt.Errorf("invalid transition: %w", transitionErr)
			}
			commit.Transition = kind
		}
		if err := appendMirrors(commit.State.Mirrors); err != nil {
			return nil, err
		}
		previousState = commit.State
		tip = commit
	}
	if tip.CommitID != tipID {
		return nil, fmt.Errorf("validated history does not end at resolved tip")
	}
	if err := topologyRaw.Sync(); err != nil {
		return nil, err
	}
	if err := topologyRaw.Close(); err != nil {
		return nil, err
	}
	topologyOpen = false
	topologyPath, err := compactMirrorTopology(workspace, topologyRawPath)
	if err != nil {
		return nil, err
	}
	if err := ids.Sync(); err != nil {
		return nil, err
	}
	history := &History{
		workspace: workspace, ids: ids, count: count, tip: tip,
		genesisFormat: genesisFormat, topologyPath: topologyPath,
	}
	idsOpen = false
	keep = true
	if err := writeValidationCache(validator.CachePath, history); err != nil {
		_ = history.Close()
		return nil, fmt.Errorf("write validated-ancestor cache: %w", err)
	}
	return history, nil
}

func compactMirrorTopology(workspace, rawPath string) (string, error) {
	firstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("derived mirror row lacks a name")
		}
		return field, nil
	}
	sortedPath := filepath.Join(workspace, "mirror-topology.sorted")
	if err := extsort.SortFiles(workspace, []string{rawPath}, sortedPath, extsort.Options{Key: firstField, MaxLineBytes: format.DefaultLimits().MaxLineBytes}); err != nil {
		return "", err
	}
	input, err := os.Open(sortedPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = input.Close() }()
	uniquePath := filepath.Join(workspace, "mirror-topology")
	output, err := os.OpenFile(uniquePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(uniquePath)
		}
	}()
	scanner := bufio.NewScanner(input)
	limits := format.DefaultLimits()
	scanner.Buffer(make([]byte, min(limits.MaxLineBytes, 64<<10)), limits.MaxLineBytes+1)
	var previousName, previousRow string
	for scanner.Scan() {
		row := scanner.Text()
		name, _, ok := strings.Cut(row, "\t")
		if !ok || name == "" {
			return "", fmt.Errorf("derived mirror row is malformed")
		}
		if name == previousName {
			if row != previousRow {
				return "", fmt.Errorf("mirror name %q was rebound or reused", name)
			}
			continue
		}
		if _, err := fmt.Fprintln(output, row); err != nil {
			return "", err
		}
		previousName, previousRow = name, row
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	keep = true
	return uniquePath, nil
}

func (validator Validator) enumerateHistoryIDs(tip string, destination *os.File) (count int, returnErr error) {
	command, err := hardenedGitCommand(validator.Repo, "rev-list", "--reverse", "--topo-order", "--max-count="+strconv.Itoa(maximumCommitCount+1), tip)
	if err != nil {
		return 0, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return 0, err
	}
	stderr := &boundedBuffer{limit: maximumGitErrorBytes}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return 0, fmt.Errorf("start git rev-list: %w", err)
	}
	started := true
	defer func() {
		if started {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	reader := bufio.NewReaderSize(stdout, 4096)
	for {
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			break
		}
		if readErr != nil {
			return 0, fmt.Errorf("read git rev-list: %w", readErr)
		}
		if len(line) != historyRecordBytes+1 || line[historyRecordBytes] != '\n' || !isGitOID(string(line[:historyRecordBytes])) {
			return 0, fmt.Errorf("history contains an invalid commit ID")
		}
		count++
		if count > maximumCommitCount {
			return 0, fmt.Errorf("metadata history exceeds %d commits", maximumCommitCount)
		}
		if _, err := destination.Write(line[:historyRecordBytes]); err != nil {
			return 0, err
		}
	}
	waitErr := command.Wait()
	started = false
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return 0, &GitExitError{Operation: "rev-list", ExitCode: exitErr.ExitCode(), Detail: strings.TrimSpace(stderr.buffer.String())}
		}
		return 0, fmt.Errorf("wait for git rev-list: %w", waitErr)
	}
	return count, nil
}
