package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"backup/internal/format"
)

func testDataPartRecord() stagedDataPart {
	return stagedDataPart{
		Entry: format.PackEntry{
			PackHash: strings.Repeat("a", 128), PartCount: 1,
			PartHash: strings.Repeat("b", 128), PartSHA256: strings.Repeat("c", 64),
			PartMD5: strings.Repeat("d", 32), PartSize: 123, ObjectID: strings.Repeat("e", 32),
		},
		RelativePath: "repair-part-" + strings.Repeat("e", 32),
	}
}

func TestDataPartRecordsStreamExistingArrayFormat(t *testing.T) {
	part := testDataPartRecord()
	record, err := json.Marshal(part)
	if err != nil {
		t.Fatal(err)
	}
	const records = 1024
	input := "[" + strings.Repeat(string(record)+",", records-1) + string(record) + "]\n"
	reader := strings.NewReader(input)
	visited := uint64(0)
	count, err := walkDataPartRecords(reader, func(index uint64, got stagedDataPart) error {
		if index != visited || got != part {
			t.Fatalf("record %d differs: %+v", index, got)
		}
		if index == 0 && len(input)-reader.Len() > maximumDataPartRecordBytes+1 {
			t.Fatal("parser read the cumulative descriptor before visiting its first record")
		}
		visited++
		return nil
	})
	if err != nil || count != records || visited != records {
		t.Fatalf("streamed array: count=%d visited=%d error=%v", count, visited, err)
	}
	stop := errors.New("visitor stopped")
	if _, err := walkDataPartRecords(strings.NewReader(input), func(uint64, stagedDataPart) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("visitor failure lost: %v", err)
	}
}

func TestDataPartRecordBoundsAndFraming(t *testing.T) {
	record, err := json.Marshal(testDataPartRecord())
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"missing-array":        string(record),
		"null-array":           "null",
		"null-record":          "[null]",
		"missing-close":        "[" + string(record),
		"trailing-json":        "[" + string(record) + "] null",
		"extra-array":          "[" + string(record) + "] []",
		"unknown-field":        "[" + strings.TrimSuffix(string(record), "}") + `,"unknown":true}]`,
		"unsafe-path":          "[" + strings.Replace(string(record), "repair-part-", "../", 1) + "]",
		"oversized-record":     `[{"relative_path":"` + strings.Repeat("x", maximumDataPartRecordBytes*4) + `"}]`,
		"oversized-whitespace": strings.Repeat(" ", maximumDataPartRecordBytes+1) + "[]",
		"oversized-trailer":    "[]" + strings.Repeat(" ", maximumDataPartRecordBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			reader := strings.NewReader(input)
			if _, err := walkDataPartRecords(reader, nil); err == nil {
				t.Fatal("invalid descriptor accepted")
			}
			if strings.HasPrefix(name, "oversized-") && len(input)-reader.Len() > maximumDataPartRecordBytes+2 {
				t.Fatalf("oversized input was not bounded: read %d bytes", len(input)-reader.Len())
			}
		})
	}
	if count, err := walkDataPartRecords(strings.NewReader("[]\n"), nil); err != nil || count != 0 {
		t.Fatalf("empty descriptor: count=%d error=%v", count, err)
	}
	part := testDataPartRecord()
	part.RelativePath = strings.Repeat("x", maximumDataPartRecordBytes-2-len(record)+len(part.RelativePath))
	largest, err := marshalDataPart(part)
	if err != nil || len(largest) != maximumDataPartRecordBytes-2 {
		t.Fatalf("largest supported writer record: size=%d error=%v", len(largest), err)
	}
	if count, err := walkDataPartRecords(strings.NewReader("["+string(largest)+","+string(largest)+"]\n"), nil); err != nil || count != 2 {
		t.Fatalf("reader rejected supported writer records: count=%d error=%v", count, err)
	}
	part.RelativePath = strings.Repeat("x", maximumDataPartRecordBytes)
	if _, err := marshalDataPart(part); err == nil {
		t.Fatal("writer accepted a record outside the reader's bound")
	}
	if _, err := walkDataPartRecords(io.MultiReader(strings.NewReader("["+string(record)), iotest.ErrReader(io.ErrUnexpectedEOF)), nil); err == nil {
		t.Fatal("descriptor read failure was ignored")
	}
}

func FuzzRepairDataPartRecords(f *testing.F) {
	record, err := json.Marshal([]stagedDataPart{testDataPartRecord()})
	if err != nil {
		f.Fatal(err)
	}
	if count, err := walkDataPartRecords(bytes.NewReader(record), nil); err != nil || count != 1 {
		f.Fatalf("valid repair seed failed: count=%d error=%v", count, err)
	}
	f.Add(record)
	f.Add([]byte("[]\n"))
	f.Add([]byte("[null]"))
	f.Add([]byte("[{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = walkDataPartRecords(bytes.NewReader(data), nil)
	})
}
