package backup

import (
	"bufio"
	"encoding/hex"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type IndexEntry struct {
	Path string
	Kind string
	Ref  string
	Size int64
	Mode string
}

type ObjectEntry struct {
	Hash    string
	PackKey string
}

type PackEntry struct {
	PackKey    string
	CipherHash string
	CipherSize int64
	CreatedUTC string
}

func ReadIndex(path string) ([]IndexEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseIndex(file)
}

func ParseIndex(reader io.Reader) ([]IndexEntry, error) {
	records, err := readTSV(reader, 5)
	if err != nil {
		return nil, err
	}
	entries := make([]IndexEntry, 0, len(records))
	for _, record := range records {
		size, err := strconv.ParseInt(record[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid size %q: %w", record[3], err)
		}
		entry := IndexEntry{
			Path: record[0],
			Kind: record[1],
			Ref:  record[2],
			Size: size,
			Mode: record[4],
		}
		if err := validateIndexEntry(entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func WriteIndex(path string, entries []IndexEntry) error {
	return writeTSVAtomic(path, func(writer *csv.Writer) error {
		for _, entry := range entries {
			record := []string{entry.Path, entry.Kind, entry.Ref, strconv.FormatInt(entry.Size, 10), entry.Mode}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
		return nil
	})
}

func ReadObjects(path string) ([]ObjectEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseObjects(file)
}

func ParseObjects(reader io.Reader) ([]ObjectEntry, error) {
	records, err := readTSV(reader, 2)
	if err != nil {
		return nil, err
	}
	entries := make([]ObjectEntry, 0, len(records))
	for _, record := range records {
		entries = append(entries, ObjectEntry{
			Hash:    record[0],
			PackKey: record[1],
		})
	}
	return entries, nil
}

func WriteObjects(path string, entries []ObjectEntry) error {
	return writeTSVAtomic(path, func(writer *csv.Writer) error {
		for _, entry := range entries {
			record := []string{entry.Hash, entry.PackKey}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
		return nil
	})
}

func ReadPacks(path string) ([]PackEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParsePacks(file)
}

func ParsePacks(reader io.Reader) ([]PackEntry, error) {
	records, err := readTSV(reader, 4)
	if err != nil {
		return nil, err
	}
	entries := make([]PackEntry, 0, len(records))
	for _, record := range records {
		size, err := strconv.ParseInt(record[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid cipher size %q: %w", record[2], err)
		}
		entries = append(entries, PackEntry{
			PackKey:    record[0],
			CipherHash: record[1],
			CipherSize: size,
			CreatedUTC: record[3],
		})
	}
	return entries, nil
}

func WritePacks(path string, entries []PackEntry) error {
	return writeTSVAtomic(path, func(writer *csv.Writer) error {
		for _, entry := range entries {
			record := []string{entry.PackKey, entry.CipherHash, strconv.FormatInt(entry.CipherSize, 10), entry.CreatedUTC}
			if err := writer.Write(record); err != nil {
				return err
			}
		}
		return nil
	})
}

func readTSV(reader io.Reader, fields int) ([][]string, error) {
	csvReader := csv.NewReader(bufio.NewReader(reader))
	csvReader.Comma = '\t'
	csvReader.FieldsPerRecord = fields
	csvReader.LazyQuotes = false
	csvReader.TrimLeadingSpace = false
	var records [][]string
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			return records, nil
		}
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
}

func writeTSVAtomic(path string, write func(writer *csv.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	writer.Comma = '\t'
	writer.UseCRLF = false
	if err := write(writer); err != nil {
		file.Close()
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func IndexEntriesByPath(entries []IndexEntry) map[string]IndexEntry {
	byPath := make(map[string]IndexEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	return byPath
}

func SortIndex(entries []IndexEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
}

func SortObjects(entries []ObjectEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Hash < entries[j].Hash
	})
}

func SortPacks(entries []PackEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PackKey < entries[j].PackKey
	})
}

func ParseTSVFromGit(repoDir string, revision string, path string) ([]byte, error) {
	// Important: preserve bytes exactly; do NOT TrimSpace. These are data files.
	output, err := runGitRaw(repoDir, "show", fmt.Sprintf("%s:%s", revision, path))
	if err != nil {
		return nil, err
	}
	return []byte(output), nil
}

func ParseIndexFromGit(repoDir string, revision string) ([]IndexEntry, error) {
	data, err := ParseTSVFromGit(repoDir, revision, "index.tsv")
	if err != nil {
		if strings.Contains(err.Error(), "fatal") {
			return nil, nil
		}
		return nil, err
	}
	return ParseIndex(strings.NewReader(string(data)))
}

func ParseObjectsFromGit(repoDir string, revision string) ([]ObjectEntry, error) {
	data, err := ParseTSVFromGit(repoDir, revision, "objects.tsv")
	if err != nil {
		if strings.Contains(err.Error(), "fatal") {
			return nil, nil
		}
		return nil, err
	}
	return ParseObjects(strings.NewReader(string(data)))
}

func ParsePacksFromGit(repoDir string, revision string) ([]PackEntry, error) {
	data, err := ParseTSVFromGit(repoDir, revision, "packs.tsv")
	if err != nil {
		if strings.Contains(err.Error(), "fatal") {
			return nil, nil
		}
		return nil, err
	}
	return ParsePacks(strings.NewReader(string(data)))
}

func validateIndexEntry(entry IndexEntry) error {
	if !strings.HasPrefix(entry.Path, "./") {
		return fmt.Errorf("invalid index path (must start with ./): %q", entry.Path)
	}
	rel := strings.TrimPrefix(entry.Path, "./")
	normalized, err := NormalizePath(rel)
	if err != nil {
		return fmt.Errorf("invalid index path %q: %w", entry.Path, err)
	}
	if normalized != entry.Path {
		return fmt.Errorf("non-canonical index path %q (expected %q)", entry.Path, normalized)
	}
	switch entry.Kind {
	case "file":
		if entry.Size < 0 {
			return fmt.Errorf("invalid file size for %q: %d", entry.Path, entry.Size)
		}
		if entry.Mode == "-" {
			return fmt.Errorf("file mode must not be '-': %q", entry.Path)
		}
		if !strings.HasPrefix(entry.Ref, "blake2b:") {
			return fmt.Errorf("invalid file ref for %q: %q", entry.Path, entry.Ref)
		}
		hash := strings.TrimPrefix(entry.Ref, "blake2b:")
		if len(hash) != 128 {
			return fmt.Errorf("invalid blake2b hash length for %q: %d", entry.Path, len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("invalid blake2b hex for %q: %w", entry.Path, err)
		}
		// Basic mode validation: must be octal digits.
		if _, err := strconv.ParseUint(entry.Mode, 8, 32); err != nil {
			return fmt.Errorf("invalid mode for %q: %q", entry.Path, entry.Mode)
		}
		return nil
	case "symlink":
		if entry.Size != 0 {
			return fmt.Errorf("symlink size must be 0 for %q", entry.Path)
		}
		if entry.Mode != "-" {
			return fmt.Errorf("symlink mode must be '-' for %q", entry.Path)
		}
		if !strings.HasPrefix(entry.Ref, "target:") {
			return fmt.Errorf("invalid symlink ref for %q: %q", entry.Path, entry.Ref)
		}
		target := strings.TrimPrefix(entry.Ref, "target:")
		if !strings.HasPrefix(target, "./") {
			return fmt.Errorf("invalid symlink target (must start with ./) for %q: %q", entry.Path, target)
		}
		targetRel := strings.TrimPrefix(target, "./")
		targetNorm, err := NormalizePath(targetRel)
		if err != nil {
			return fmt.Errorf("invalid symlink target path %q: %w", target, err)
		}
		if targetNorm != target {
			return fmt.Errorf("non-canonical symlink target %q (expected %q)", target, targetNorm)
		}
		return nil
	default:
		return fmt.Errorf("unknown entry kind: %q", entry.Kind)
	}
}
