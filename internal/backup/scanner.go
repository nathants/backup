package backup

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type FileHash struct {
	Hash string
	Path string
	Size int64
	Mode string
}

type ScanResult struct {
	Entries []IndexEntry
	Files   []FileHash
}

func ScanRoot(root string, ignore Ignore) (ScanResult, error) {
	var entries []IndexEntry
	fileByHash := map[string]FileHash{}

	walkFn := func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		normalized, err := NormalizePath(relPath)
		if err != nil {
			return err
		}
		if normalized == "./.backup" || strings.HasPrefix(normalized, "./.backup/") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ignore.Matches(normalized) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		if mode.IsRegular() {
			hash, size, err := hashFile(path)
			if err != nil {
				return err
			}
			modeStr := fmt.Sprintf("%03o", mode.Perm())
			entries = append(entries, IndexEntry{
				Path: normalized,
				Kind: "file",
				Ref:  "blake2b:" + hash,
				Size: size,
				Mode: modeStr,
			})
			if _, ok := fileByHash[hash]; !ok {
				fileByHash[hash] = FileHash{
					Hash: hash,
					Path: path,
					Size: size,
					Mode: modeStr,
				}
			}
			return nil
		}
		if mode&fs.ModeSymlink != 0 {
			symlinkEntry, err := scanSymlink(root, path, normalized)
			if err != nil {
				return err
			}
			if symlinkEntry != nil {
				entries = append(entries, *symlinkEntry)
			}
			return nil
		}
		return nil
	}

	err := filepath.WalkDir(root, walkFn)
	if err != nil {
		return ScanResult{}, err
	}

	SortIndex(entries)
	files := make([]FileHash, 0, len(fileByHash))
	for _, value := range fileByHash {
		files = append(files, value)
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Hash < files[j].Hash
	})
	return ScanResult{Entries: entries, Files: files}, nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	hash, err := blake2b.New512(nil)
	if err != nil {
		return "", 0, err
	}
	count, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), count, nil
}

func scanSymlink(root string, fullPath string, normalized string) (*IndexEntry, error) {
	linkTarget, err := os.Readlink(fullPath)
	if err != nil {
		return nil, err
	}
	if linkTarget == "" {
		return nil, nil
	}
	linkDir := filepath.Dir(fullPath)
	resolved := linkTarget
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(linkDir, resolved)
	}
	realPath, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return nil, nil
	}
	if info.IsDir() {
		return nil, nil
	}
	if !IsWithinRoot(root, realPath) {
		return nil, nil
	}
	targetPath, err := NormalizeTargetPath(root, realPath)
	if err != nil {
		return nil, err
	}
	entry := IndexEntry{
		Path: normalized,
		Kind: "symlink",
		Ref:  "target:" + targetPath,
		Size: 0,
		Mode: "-",
	}
	return &entry, nil
}
