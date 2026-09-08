package format

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

const (
	MaximumIgnoreBytes     = int64(256 << 20)
	MaximumPublicKeysBytes = int64(16 << 20)
	MaximumMirrorsBytes    = int64(64 << 20)
)

type Ignore struct {
	patterns []string
	compiled []*regexp.Regexp
}

func ParseIgnore(reader io.Reader, limits Limits) (Ignore, error) {
	lines, err := readConfigLines(reader, limits, true)
	if err != nil {
		return Ignore{}, fmt.Errorf("ignore: %w", err)
	}
	ignore := Ignore{}
	for lineIndex, line := range lines {
		if line == "" {
			continue
		}
		compiled, compileErr := regexp.Compile(line)
		if compileErr != nil {
			return Ignore{}, fmt.Errorf("ignore line %d: invalid regular expression: %w", lineIndex+1, compileErr)
		}
		ignore.patterns = append(ignore.patterns, line)
		ignore.compiled = append(ignore.compiled, compiled)
	}
	return ignore, nil
}

func (ignore Ignore) Match(value string) bool {
	for _, expression := range ignore.compiled {
		if expression.MatchString(value) {
			return true
		}
	}
	return false
}

func (ignore Ignore) Patterns() []string {
	return append([]string(nil), ignore.patterns...)
}

func ParsePublicKeys(reader io.Reader, limits Limits) ([][]byte, error) {
	lines, err := readConfigLines(reader, limits, false)
	if err != nil {
		return nil, fmt.Errorf(".publickeys: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf(".publickeys is empty")
	}
	keys := make([][]byte, 0, len(lines))
	previous := ""
	for lineIndex, line := range lines {
		if !publicKeyPattern.MatchString(line) {
			return nil, fmt.Errorf(".publickeys line %d is not a lowercase serialized public key", lineIndex+1)
		}
		if lineIndex > 0 && previous >= line {
			return nil, fmt.Errorf(".publickeys is not sorted uniquely at line %d", lineIndex+1)
		}
		decoded, decodeErr := hex.DecodeString(line)
		if decodeErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf(".publickeys line %d is malformed", lineIndex+1)
		}
		keys = append(keys, decoded)
		previous = line
	}
	return keys, nil
}

func MarshalPublicKeys(keys [][]byte) ([]byte, error) {
	rows := make([][]string, len(keys))
	previous := ""
	for index, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("public key %d has %d bytes, expected 32", index+1, len(key))
		}
		serialized := hex.EncodeToString(key)
		if index > 0 && previous >= serialized {
			return nil, fmt.Errorf("public keys are not sorted uniquely")
		}
		rows[index] = []string{serialized}
		previous = serialized
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("public key list is empty")
	}
	return marshalRows(rows)
}

func RequireRecoveryRecipient(keys [][]byte, fingerprint string) error {
	if !fingerprintPattern.MatchString(fingerprint) {
		return fmt.Errorf("invalid recovery recipient fingerprint %q", fingerprint)
	}
	count := 0
	for _, key := range keys {
		if RecoveryFingerprint(key) == fingerprint {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("recovery recipient fingerprint occurs %d times, expected exactly once", count)
	}
	return nil
}

func readConfigLines(input io.Reader, limits Limits, allowEmpty bool) ([]string, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	tracked := &trackedReader{r: input, max: limits.MaxFileBytes}
	scanner := bufio.NewScanner(tracked)
	scanner.Split(splitLF)
	initial := limits.MaxLineBytes
	if initial > 64<<10 {
		initial = 64 << 10
	}
	scanner.Buffer(make([]byte, initial), limits.MaxLineBytes+1)
	lines := make([]string, 0)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(lines) >= limits.MaxRecords {
			return nil, fmt.Errorf("file exceeds %d lines", limits.MaxRecords)
		}
		if len(line) > limits.MaxLineBytes {
			return nil, fmt.Errorf("line exceeds %d bytes", limits.MaxLineBytes)
		}
		if !utf8.Valid(line) {
			return nil, fmt.Errorf("line %d is not valid UTF-8", len(lines)+1)
		}
		if len(lines) == 0 && bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf}) {
			return nil, fmt.Errorf("UTF-8 BOM is forbidden")
		}
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			return nil, fmt.Errorf("line %d contains a forbidden control character", len(lines)+1)
		}
		if !allowEmpty && len(line) == 0 {
			return nil, fmt.Errorf("blank line %d is forbidden", len(lines)+1)
		}
		lines = append(lines, string(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if tracked.over || tracked.total > limits.MaxFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", limits.MaxFileBytes)
	}
	if tracked.haveLast && tracked.last != '\n' {
		return nil, fmt.Errorf("nonempty file must end in LF")
	}
	return lines, nil
}
