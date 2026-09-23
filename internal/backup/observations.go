package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"backup/internal/format"
)

// The disposable lookup table holds only offsets into the validated observation
// file. Keeping it on disk bounds heap use independently of the path count.
// A digest selects a bucket; the actual path must also match before reuse.
const observationSlotBytes = 32 + 8 + 4

type observationIndex struct {
	file     *os.File
	rows     *os.File
	capacity uint64
}

func newObservationIndex(ctx context.Context, path string, rows *os.File) (_ *observationIndex, returnErr error) {
	var count uint64
	if err := format.WalkIndex(rows, format.DefaultLimits(), func(entry format.IndexEntry) error {
		if entry.Kind == format.KindFile {
			count++
		}
		return ctx.Err()
	}); err != nil {
		return nil, err
	}
	capacity := uint64(2)
	for capacity/2 < count {
		if capacity > uint64(^uint64(0)>>1)/observationSlotBytes/2 {
			return nil, fmt.Errorf("observation index is not representable")
		}
		capacity *= 2
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = file.Close()
		}
	}()
	if err := file.Truncate(int64(capacity * observationSlotBytes)); err != nil {
		return nil, err
	}
	index := &observationIndex{file: file, rows: rows, capacity: capacity}
	if _, err := rows.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var offset uint64
	err = format.WalkIndex(rows, format.DefaultLimits(), func(entry format.IndexEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		row, err := format.MarshalIndexEntry(entry)
		if err != nil {
			return err
		}
		if len(row) > format.DefaultLimits().MaxLineBytes+1 || offset > uint64(^uint64(0)>>1)-uint64(len(row)) {
			return fmt.Errorf("observation row is not representable")
		}
		if entry.Kind == format.KindFile {
			digest := sha256.Sum256([]byte(entry.Path))
			var record [observationSlotBytes]byte
			for probe := uint64(0); ; probe++ {
				if probe == capacity {
					return fmt.Errorf("observation index is full")
				}
				slot := (binary.BigEndian.Uint64(digest[:8]) + probe) & (capacity - 1)
				if _, err := file.ReadAt(record[:], int64(slot*observationSlotBytes)); err != nil {
					return err
				}
				if binary.BigEndian.Uint32(record[40:]) != 0 {
					continue
				}
				copy(record[:32], digest[:])
				binary.BigEndian.PutUint64(record[32:40], offset)
				binary.BigEndian.PutUint32(record[40:], uint32(len(row)))
				if _, err := file.WriteAt(record[:], int64(slot*observationSlotBytes)); err != nil {
					return err
				}
				break
			}
		}
		offset += uint64(len(row))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}

func (index *observationIndex) lookup(path string) (*format.IndexEntry, error) {
	digest := sha256.Sum256([]byte(path))
	var record [observationSlotBytes]byte
	for probe := uint64(0); probe < index.capacity; probe++ {
		slot := (binary.BigEndian.Uint64(digest[:8]) + probe) & (index.capacity - 1)
		if _, err := index.file.ReadAt(record[:], int64(slot*observationSlotBytes)); err != nil {
			return nil, err
		}
		length := binary.BigEndian.Uint32(record[40:])
		if length == 0 {
			return nil, nil
		}
		if !bytes.Equal(record[:32], digest[:]) {
			continue
		}
		offset := binary.BigEndian.Uint64(record[32:40])
		if length > uint32(format.DefaultLimits().MaxLineBytes+1) || offset > uint64(^uint64(0)>>1)-uint64(length) {
			return nil, fmt.Errorf("invalid observation index record")
		}
		row := make([]byte, int(length))
		if _, err := index.rows.ReadAt(row, int64(offset)); err != nil {
			return nil, err
		}
		limits := format.DefaultLimits()
		limits.MaxLineBytes, limits.MaxFieldBytes, limits.MaxRecords = len(row), len(row), 1
		var entry format.IndexEntry
		if err := format.WalkIndex(bytes.NewReader(row), limits, func(e format.IndexEntry) error { entry = e; return nil }); err != nil {
			return nil, err
		}
		if entry.Path == path && entry.Kind == format.KindFile {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("observation index has no empty slot")
}

// Observation inventories may contain former leaves and their descendants from
// different scans. They are not snapshots. Only sorted, unique, valid rows are
// required here; the active plan still receives normal snapshot validation.
func mergeObservations(ctx context.Context, previous, current io.Reader, output io.Writer) error {
	stream := func(reader io.Reader) streamedIndex {
		return startIndexStream(func(visit func(format.IndexEntry) error) error {
			return format.WalkIndex(reader, format.DefaultLimits(), func(entry format.IndexEntry) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				return visit(entry)
			})
		})
	}
	old, next := stream(previous), stream(current)
	a, aOK := <-old.entries
	b, bOK := <-next.entries
	var writeErr error
	emit := func(entry format.IndexEntry) {
		if writeErr != nil {
			return
		}
		var row []byte
		row, writeErr = format.MarshalIndexEntry(entry)
		if writeErr == nil {
			_, writeErr = output.Write(row)
		}
	}
	for aOK || bOK {
		switch {
		case !bOK || aOK && a.Path < b.Path:
			emit(a)
			a, aOK = <-old.entries
		case !aOK || b.Path < a.Path:
			emit(b)
			b, bOK = <-next.entries
		default:
			emit(b)
			a, aOK = <-old.entries
			b, bOK = <-next.entries
		}
	}
	return errors.Join(writeErr, <-old.done, <-next.done)
}
