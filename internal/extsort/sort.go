// Package extsort provides a bounded-memory external sorter for canonical
// LF-terminated records.
package extsort

import (
	"bufio"
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"backup/internal/securefs"
	"golang.org/x/sys/unix"
)

const (
	defaultMemoryBytes = 32 << 20
	defaultMaxLine     = 16 << 10
	defaultMaxOpen     = 64
)

type KeyFunc func(record []byte) ([]byte, error)

type Options struct {
	MemoryBytes  int
	MaxLineBytes int
	MaxOpenFiles int
	Unique       bool
	Key          KeyFunc
}

type record struct {
	data []byte
	key  []byte
}

// SortFiles sorts all records from inputs into output. Inputs and output must
// be ordinary files; every nonempty input must end in LF. Publication is an
// fsynced atomic rename in output's containing directory.
func SortFiles(workspace string, inputs []string, output string, options Options) error {
	options = normalized(options)
	if workspace == "" || output == "" || len(inputs) == 0 {
		return fmt.Errorf("external sort requires workspace, input, and output paths")
	}
	stage, err := os.MkdirTemp(workspace, ".external-sort-")
	if err != nil {
		return err
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = securefs.RemoveTree(stage)
		return err
	}
	defer securefs.RemoveTree(stage)

	var runs []string
	chunk := make([]record, 0, 1024)
	used := 0
	spill := func() error {
		if len(chunk) == 0 {
			return nil
		}
		sort.Slice(chunk, func(left, right int) bool {
			comparison := bytes.Compare(chunk[left].key, chunk[right].key)
			if comparison != 0 {
				return comparison < 0
			}
			return bytes.Compare(chunk[left].data, chunk[right].data) < 0
		})
		if options.Unique {
			for index := 1; index < len(chunk); index++ {
				if bytes.Equal(chunk[index-1].key, chunk[index].key) {
					return fmt.Errorf("external sort encountered duplicate key %q", printableKey(chunk[index].key))
				}
			}
		}
		path := filepath.Join(stage, fmt.Sprintf("run-%08d", len(runs)))
		if err := writeRecords(path, chunk); err != nil {
			return err
		}
		runs = append(runs, path)
		chunk = chunk[:0]
		used = 0
		return nil
	}
	for _, input := range inputs {
		reader, err := openLineReader(input, options.MaxLineBytes)
		if err != nil {
			return err
		}
		for reader.Scan() {
			data := append([]byte(nil), reader.Bytes()...)
			key, err := options.Key(data)
			if err != nil {
				reader.Close()
				return fmt.Errorf("extract sort key from %q: %w", input, err)
			}
			key = append([]byte(nil), key...)
			if len(key) == 0 {
				reader.Close()
				return fmt.Errorf("external sort key is empty")
			}
			cost := len(data) + len(key) + 64
			if len(chunk) != 0 && used > options.MemoryBytes-cost {
				if err := spill(); err != nil {
					reader.Close()
					return err
				}
			}
			chunk = append(chunk, record{data: data, key: key})
			used += cost
		}
		if err := reader.Err(); err != nil {
			reader.Close()
			return fmt.Errorf("read sort input %q: %w", input, err)
		}
		if err := reader.Close(); err != nil {
			return err
		}
	}
	if err := spill(); err != nil {
		return err
	}
	if len(runs) == 0 {
		empty := filepath.Join(stage, "empty")
		if err := writeRecords(empty, nil); err != nil {
			return err
		}
		runs = append(runs, empty)
	}

	pass := 0
	for len(runs) > 1 {
		var next []string
		for start := 0; start < len(runs); start += options.MaxOpenFiles {
			end := start + options.MaxOpenFiles
			if end > len(runs) {
				end = len(runs)
			}
			path := filepath.Join(stage, fmt.Sprintf("merge-%04d-%08d", pass, len(next)))
			if err := mergeRuns(runs[start:end], path, options); err != nil {
				return err
			}
			next = append(next, path)
		}
		for _, path := range runs {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		runs = next
		pass++
	}
	return publishFile(runs[0], output)
}

func normalized(options Options) Options {
	if options.MemoryBytes <= 0 {
		options.MemoryBytes = defaultMemoryBytes
	}
	if options.MaxLineBytes <= 0 {
		options.MaxLineBytes = defaultMaxLine
	}
	if options.MaxOpenFiles < 2 {
		options.MaxOpenFiles = defaultMaxOpen
	}
	if options.Key == nil {
		options.Key = func(record []byte) ([]byte, error) { return record, nil }
	}
	return options
}

func writeRecords(path string, records []record) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(file, 256<<10)
	for _, record := range records {
		if _, err := writer.Write(record.data); err != nil {
			file.Close()
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			file.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

type lineReader struct {
	file    *os.File
	scanner *bufio.Scanner
}

func openLineReader(path string, maxLine int) (*lineReader, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("sort input %q is not a regular file", path)
	}
	if info.Size() > 0 {
		var last [1]byte
		if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
			file.Close()
			return nil, err
		}
		if last[0] != '\n' {
			file.Close()
			return nil, fmt.Errorf("sort input %q does not end in LF", path)
		}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, min(maxLine, 64<<10)), maxLine+1)
	return &lineReader{file: file, scanner: scanner}, nil
}

func (reader *lineReader) Scan() bool    { return reader.scanner.Scan() }
func (reader *lineReader) Bytes() []byte { return reader.scanner.Bytes() }
func (reader *lineReader) Err() error    { return reader.scanner.Err() }
func (reader *lineReader) Close() error  { return reader.file.Close() }

type mergeNode struct {
	record record
	run    int
}

type mergeHeap []mergeNode

func (items mergeHeap) Len() int { return len(items) }
func (items mergeHeap) Less(left, right int) bool {
	comparison := bytes.Compare(items[left].record.key, items[right].record.key)
	if comparison != 0 {
		return comparison < 0
	}
	return bytes.Compare(items[left].record.data, items[right].record.data) < 0
}
func (items mergeHeap) Swap(left, right int) { items[left], items[right] = items[right], items[left] }
func (items *mergeHeap) Push(value any)      { *items = append(*items, value.(mergeNode)) }
func (items *mergeHeap) Pop() any {
	old := *items
	last := old[len(old)-1]
	*items = old[:len(old)-1]
	return last
}

func mergeRuns(inputs []string, output string, options Options) (returnErr error) {
	readers := make([]*lineReader, len(inputs))
	defer func() {
		for _, reader := range readers {
			if reader != nil {
				returnErr = errors.Join(returnErr, reader.Close())
			}
		}
	}()
	queue := &mergeHeap{}
	heap.Init(queue)
	advance := func(index int) error {
		reader := readers[index]
		if !reader.Scan() {
			return reader.Err()
		}
		data := append([]byte(nil), reader.Bytes()...)
		key, err := options.Key(data)
		if err != nil {
			return err
		}
		heap.Push(queue, mergeNode{record: record{data: data, key: append([]byte(nil), key...)}, run: index})
		return nil
	}
	for index, input := range inputs {
		reader, err := openLineReader(input, options.MaxLineBytes)
		if err != nil {
			return err
		}
		readers[index] = reader
		if err := advance(index); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	writer := bufio.NewWriterSize(file, 256<<10)
	var previousKey []byte
	for queue.Len() != 0 {
		node := heap.Pop(queue).(mergeNode)
		if options.Unique && previousKey != nil && bytes.Equal(previousKey, node.record.key) {
			return fmt.Errorf("external sort encountered duplicate key %q", printableKey(node.record.key))
		}
		if _, err := writer.Write(node.record.data); err != nil {
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			return err
		}
		previousKey = append(previousKey[:0], node.record.key...)
		if err := advance(node.run); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	return file.Sync()
}

func publishFile(source, destination string) error {
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".sorted-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(temporary, input, make([]byte, 1<<20))
	closeErr := input.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	published = true
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func printableKey(key []byte) string {
	if len(key) > 128 {
		key = key[:128]
	}
	return string(key)
}
