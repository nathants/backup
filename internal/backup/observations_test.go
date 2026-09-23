package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestObservationIndexRoundTripAndMisses(t *testing.T) {
	var data bytes.Buffer
	for n := 0; n < 2000; n++ {
		entry := format.IndexEntry{Path: fmt.Sprintf("./dir/%04d spaced-λ", n), Kind: format.KindFile, Ref: "blake2b:" + strings.Repeat("a", 128), Size: uint64(n), Mode: 0600, MtimeNS: -int64(n)}
		if n%5 == 0 {
			entry = format.IndexEntry{Path: entry.Path, Kind: format.KindSymlink, Ref: "target:./"}
		}
		row, err := format.MarshalIndexEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		data.Write(row)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "rows")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	index, err := newObservationIndex(context.Background(), filepath.Join(directory, "index"), rows)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = index.file.Close() }()
	for n := 1999; n >= 0; n-- {
		entry, err := index.lookup(fmt.Sprintf("./dir/%04d spaced-λ", n))
		if err != nil {
			t.Fatal(err)
		}
		if n%5 == 0 {
			if entry != nil {
				t.Fatalf("reused symlink: %+v", entry)
			}
		} else if entry == nil || entry.Size != uint64(n) || entry.MtimeNS != -int64(n) {
			t.Fatalf("wrong observation for %d: %+v", n, entry)
		}
	}
	if entry, err := index.lookup("./absent"); err != nil || entry != nil {
		t.Fatalf("missing path: %+v %v", entry, err)
	}
	// Bucket digests are not authority: even a matching digest must have the
	// expected canonical path in its referenced row.
	var slot [observationSlotBytes]byte
	var occupied int64
	for ; ; occupied += observationSlotBytes {
		if _, err := index.file.ReadAt(slot[:], occupied); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint32(slot[40:]) != 0 {
			break
		}
	}
	oldOffset := binary.BigEndian.Uint64(slot[32:40])
	length := binary.BigEndian.Uint32(slot[40:])
	row := make([]byte, length)
	if _, err := rows.ReadAt(row, int64(oldOffset)); err != nil {
		t.Fatal(err)
	}
	name := string(bytes.SplitN(row, []byte{'\t'}, 2)[0])
	// The first row is a symlink with a different path; a swapped offset must
	// never return it as a cached regular-file observation for name.
	binary.BigEndian.PutUint64(slot[32:40], 0)
	binary.BigEndian.PutUint32(slot[40:], uint32(bytes.IndexByte(data.Bytes(), '\n')+1))
	if _, err := index.file.WriteAt(slot[:], occupied); err != nil {
		t.Fatal(err)
	}
	if entry, err := index.lookup(name); err != nil || entry != nil {
		t.Fatalf("substituted observation reused: %+v %v", entry, err)
	}
	binary.BigEndian.PutUint32(slot[40:], ^uint32(0))
	if _, err := index.file.WriteAt(slot[:], occupied); err != nil {
		t.Fatal(err)
	}
	if _, err := index.lookup(name); err == nil {
		t.Fatal("unbounded row length accepted")
	}
}

func TestMergeObservationsPrefersCurrentAndPropagatesFailures(t *testing.T) {
	entry := func(path, target string) string {
		t.Helper()
		row, err := format.MarshalIndexEntry(format.IndexEntry{Path: path, Kind: format.KindSymlink, Ref: "target:" + target})
		if err != nil {
			t.Fatal(err)
		}
		return string(row)
	}
	old := entry("./a", "./old") + entry("./z", "./")
	current := entry("./a", "./new") + entry("./b", "./")
	var output bytes.Buffer
	if err := mergeObservations(context.Background(), strings.NewReader(old), strings.NewReader(current), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != current+entry("./z", "./") {
		t.Fatalf("wrong union: %s", output.String())
	}
	if err := mergeObservations(context.Background(), strings.NewReader(old), strings.NewReader(current), observationFailWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write failure: %v", err)
	}
	if err := mergeObservations(context.Background(), strings.NewReader(old+old), strings.NewReader(current), io.Discard); err == nil {
		t.Fatal("invalid inventory accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := mergeObservations(ctx, strings.NewReader(old), strings.NewReader(current), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

type observationFailWriter struct{}

func (observationFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
