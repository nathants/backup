// Package format implements the canonical, versioned on-disk metadata formats.
// It deliberately does not use encoding/csv: quoting and escaping are not part
// of the format.
package format

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxInt64Text  = "9223372036854775807"
	minInt64Text  = "-9223372036854775808"
	maxUint64Text = "18446744073709551615"
)

// Limits bounds parsing of metadata that may have come from an untrusted Git
// repository or object mirror. Callers may tighten these limits by operation.
type Limits struct {
	MaxFileBytes  int64
	MaxLineBytes  int
	MaxFieldBytes int
	MaxRecords    int
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:  math.MaxInt64,
		MaxLineBytes:  16 << 10,
		MaxFieldBytes: 8 << 10,
		MaxRecords:    math.MaxInt,
	}
}

func (limits Limits) validate() error {
	if limits.MaxFileBytes <= 0 || limits.MaxLineBytes <= 0 || limits.MaxFieldBytes <= 0 || limits.MaxRecords <= 0 {
		return fmt.Errorf("all parser limits must be positive")
	}
	if int64(limits.MaxLineBytes) > limits.MaxFileBytes {
		return fmt.Errorf("maximum line size exceeds maximum file size")
	}
	if limits.MaxFieldBytes > limits.MaxLineBytes {
		return fmt.Errorf("maximum field size exceeds maximum line size")
	}
	return nil
}

type trackedReader struct {
	r        io.Reader
	max      int64
	total    int64
	last     byte
	haveLast bool
	over     bool
}

func (reader *trackedReader) Read(data []byte) (int, error) {
	if reader.over {
		return 0, fmt.Errorf("metadata exceeds %d bytes", reader.max)
	}
	if reader.total == reader.max {
		var extra [1]byte
		n, err := reader.r.Read(extra[:])
		if n != 0 {
			reader.over = true
			return 0, fmt.Errorf("metadata exceeds %d bytes", reader.max)
		}
		return 0, err
	}
	remaining := reader.max - reader.total
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	n, err := reader.r.Read(data)
	if n > 0 {
		reader.total += int64(n)
		reader.last = data[n-1]
		reader.haveLast = true
	}
	return n, err
}

func readRows(input io.Reader, limits Limits) ([][]string, error) {
	rows := make([][]string, 0)
	if err := scanRows(input, limits, func(_ int, fields []string) error {
		rows = append(rows, fields)
		return nil
	}); err != nil {
		return nil, err
	}
	return rows, nil
}

func scanRows(input io.Reader, limits Limits, visit func(record int, fields []string) error) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if visit == nil {
		return fmt.Errorf("row visitor is required")
	}
	tracked := &trackedReader{r: input, max: limits.MaxFileBytes}
	scanner := bufio.NewScanner(tracked)
	scanner.Split(splitLF)
	initial := limits.MaxLineBytes
	if initial > 64<<10 {
		initial = 64 << 10
	}
	scanner.Buffer(make([]byte, initial), limits.MaxLineBytes+1)
	record := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > limits.MaxLineBytes {
			return fmt.Errorf("metadata line exceeds %d bytes", limits.MaxLineBytes)
		}
		if record >= limits.MaxRecords {
			return fmt.Errorf("metadata exceeds %d records", limits.MaxRecords)
		}
		record++
		if !utf8.Valid(line) {
			return fmt.Errorf("metadata is not valid UTF-8 at record %d", record)
		}
		if record == 1 && bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf}) {
			return fmt.Errorf("metadata must not contain a UTF-8 BOM")
		}
		if len(line) == 0 {
			return fmt.Errorf("empty metadata record %d", record)
		}
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			return fmt.Errorf("metadata record %d contains a forbidden control character", record)
		}
		fieldsBytes := bytes.Split(line, []byte{'\t'})
		fields := make([]string, len(fieldsBytes))
		for index, field := range fieldsBytes {
			if len(field) == 0 {
				return fmt.Errorf("metadata record %d field %d is empty", record, index+1)
			}
			if len(field) > limits.MaxFieldBytes {
				return fmt.Errorf("metadata record %d field %d exceeds %d bytes", record, index+1, limits.MaxFieldBytes)
			}
			fields[index] = string(field)
		}
		if err := visit(record, fields); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read canonical metadata: %w", err)
	}
	if tracked.over || tracked.total > limits.MaxFileBytes {
		return fmt.Errorf("metadata exceeds %d bytes", limits.MaxFileBytes)
	}
	if tracked.haveLast && tracked.last != '\n' {
		return fmt.Errorf("nonempty canonical metadata must end in LF")
	}
	return nil
}

func splitLF(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		return index + 1, data[:index], nil
	}
	if atEOF && len(data) != 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func marshalRows(rows [][]string) ([]byte, error) {
	var output bytes.Buffer
	for rowIndex, row := range rows {
		if len(row) == 0 {
			return nil, fmt.Errorf("record %d has no fields", rowIndex+1)
		}
		for fieldIndex, field := range row {
			if err := validateRawField(field); err != nil {
				return nil, fmt.Errorf("record %d field %d: %w", rowIndex+1, fieldIndex+1, err)
			}
			if fieldIndex != 0 {
				output.WriteByte('\t')
			}
			output.WriteString(field)
		}
		output.WriteByte('\n')
	}
	return output.Bytes(), nil
}

func validateRawField(value string) error {
	if value == "" {
		return fmt.Errorf("empty field")
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("field is not valid UTF-8")
	}
	if strings.ContainsAny(value, "\x00\t\r\n") {
		return fmt.Errorf("field contains a forbidden control character")
	}
	if strings.HasPrefix(value, "\ufeff") {
		return fmt.Errorf("field starts with a UTF-8 BOM")
	}
	return nil
}

func requireFieldCount(row []string, count, record int) error {
	if len(row) != count {
		return fmt.Errorf("record %d has %d fields, expected %d", record, len(row), count)
	}
	return nil
}

func parseUint(value string, bits int, label string) (uint64, error) {
	if !canonicalUnsigned(value) {
		return 0, fmt.Errorf("invalid canonical %s %q", label, value)
	}
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", label, value, err)
	}
	return parsed, nil
}

func parseInt64(value, label string) (int64, error) {
	if !canonicalSigned(value) {
		return 0, fmt.Errorf("invalid canonical %s %q", label, value)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", label, value, err)
	}
	return parsed, nil
}

func canonicalUnsigned(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] == '0' {
		return false
	}
	for _, char := range []byte(value) {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(value) < len(maxUint64Text) || len(value) == len(maxUint64Text) && value <= maxUint64Text
}

func canonicalSigned(value string) bool {
	if canonicalUnsigned(value) {
		return len(value) < len(maxInt64Text) || len(value) == len(maxInt64Text) && value <= maxInt64Text
	}
	if len(value) < 2 || value[0] != '-' || value[1] == '0' {
		return false
	}
	for _, char := range []byte(value[1:]) {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(value) < len(minInt64Text) || len(value) == len(minInt64Text) && value <= minInt64Text
}

func uintText(value uint64) string { return strconv.FormatUint(value, 10) }
func intText(value int64) string   { return strconv.FormatInt(value, 10) }
