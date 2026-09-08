package repository

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"backup/internal/format"
	"backup/internal/securefs"
)

const historyRecordBytes = 64

// History is a validated linear Git history whose commit IDs and permanent
// mirror-name ledger are file-backed. Only the selected tip state and the
// fixed repository format are retained in memory.
type History struct {
	workspace     string
	ids           *os.File
	count         int
	tip           ValidatedCommit
	genesisFormat format.RepositoryFormat
	topologyPath  string
	closed        bool
}

func (history *History) Len() int {
	if history == nil {
		return 0
	}
	return history.count
}

func (history *History) Tip() (ValidatedCommit, error) {
	if history == nil || history.closed || history.count == 0 {
		return ValidatedCommit{}, fmt.Errorf("metadata history is unavailable")
	}
	return history.tip, nil
}

func (history *History) GenesisFormat() (format.RepositoryFormat, error) {
	if history == nil || history.closed || history.count == 0 {
		return format.RepositoryFormat{}, fmt.Errorf("metadata history is unavailable")
	}
	return history.genesisFormat, nil
}

func (history *History) CommitID(index int) (string, error) {
	if history == nil || history.closed || history.ids == nil || index < 0 || index >= history.count {
		return "", fmt.Errorf("invalid metadata history position")
	}
	var record [historyRecordBytes]byte
	count, err := history.ids.ReadAt(record[:], int64(index)*historyRecordBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if count != len(record) || !isGitOID(string(record[:])) {
		return "", fmt.Errorf("file-backed metadata history changed")
	}
	return string(record[:]), nil
}

func (history *History) WalkIDs(visit func(index int, commitID string) error) error {
	if history == nil || history.closed || history.ids == nil || visit == nil {
		return fmt.Errorf("metadata history is unavailable")
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(history.ids, 0, int64(history.count)*historyRecordBytes), 256<<10)
	var record [historyRecordBytes]byte
	for index := 0; index < history.count; index++ {
		if _, err := io.ReadFull(reader, record[:]); err != nil {
			return fmt.Errorf("read file-backed metadata history: %w", err)
		}
		commitID := string(record[:])
		if !isGitOID(commitID) {
			return fmt.Errorf("file-backed metadata history changed")
		}
		if err := visit(index, commitID); err != nil {
			return err
		}
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("file-backed metadata history has trailing data")
		}
		return err
	}
	return nil
}

func (history *History) IndexOf(commitID string) (int, bool, error) {
	if !isGitOID(commitID) {
		return -1, false, fmt.Errorf("invalid commit ID")
	}
	found := -1
	err := history.WalkIDs(func(index int, candidate string) error {
		if candidate == commitID {
			found = index
			return io.EOF
		}
		return nil
	})
	if errors.Is(err, io.EOF) {
		return found, true, nil
	}
	if err != nil {
		return -1, false, err
	}
	return -1, false, nil
}

// ValidateMirrorTopology rejects rebinding or reuse of any mirror name that
// appeared in the validated history, including names absent from the tip.
func (history *History) ValidateMirrorTopology(mirrors []format.Mirror) error {
	if history == nil || history.closed || history.topologyPath == "" {
		return fmt.Errorf("metadata history topology is unavailable")
	}
	canonical, err := format.MarshalMirrors(mirrors)
	if err != nil {
		return err
	}
	candidate := make(map[string]string, len(mirrors))
	for _, row := range bytes.Split(bytes.TrimSuffix(canonical, []byte{'\n'}), []byte{'\n'}) {
		if len(row) == 0 {
			continue
		}
		name, _, ok := bytes.Cut(row, []byte{'\t'})
		if !ok {
			return fmt.Errorf("canonical mirror row lacks a name")
		}
		candidate[string(name)] = string(row)
	}
	file, err := os.Open(history.topologyPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	limits := format.DefaultLimits()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, min(limits.MaxLineBytes, 64<<10)), limits.MaxLineBytes+1)
	for scanner.Scan() {
		row := scanner.Text()
		name, _, ok := strings.Cut(row, "\t")
		if !ok || name == "" {
			return fmt.Errorf("file-backed mirror topology changed")
		}
		if expected, present := candidate[name]; present && expected != row {
			return fmt.Errorf("mirror name %q was rebound or reused", name)
		}
	}
	return scanner.Err()
}

func (history *History) topologySnapshot(maximum int64) ([]format.Mirror, bool, error) {
	if history == nil || history.closed || maximum < 0 {
		return nil, false, fmt.Errorf("metadata history topology is unavailable")
	}
	file, err := os.Open(history.topologyPath)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maximum {
		return nil, false, nil
	}
	mirrors, err := format.ParseMirrors(bytes.NewReader(data), format.DefaultLimits())
	if err != nil {
		return nil, false, err
	}
	return mirrors, true, nil
}

func (history *History) Close() error {
	if history == nil || history.closed {
		return nil
	}
	history.closed = true
	var result error
	if history.ids != nil {
		result = errors.Join(result, history.ids.Close())
		history.ids = nil
	}
	if history.workspace != "" {
		result = errors.Join(result, securefs.RemoveTree(history.workspace))
		history.workspace = ""
	}
	return result
}
