package backup

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

type DiffKind int

const (
	DiffAddition DiffKind = iota
	DiffDeletion
	DiffChange
)

type IndexDiff struct {
	Kind DiffKind
	New  IndexEntry
	Old  IndexEntry
}

func InitRepo(config Config) error {
	backupDir := config.BackupDir()
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(backupDir, ".git")); os.IsNotExist(err) {
		err = gitInit(backupDir)
		if err != nil {
			return err
		}
	}
	ignorePath := filepath.Join(backupDir, "ignore")
	indexPath := filepath.Join(backupDir, "index.tsv")
	objectsPath := filepath.Join(backupDir, "objects.tsv")
	packsPath := filepath.Join(backupDir, "packs.tsv")
	publicKeysPath := filepath.Join(backupDir, ".publickeys")
	paths := []string{ignorePath, indexPath, objectsPath, packsPath}

	if _, err := os.Stat(publicKeysPath); os.IsNotExist(err) {
		key := strings.TrimSpace(os.Getenv("GIT_REMOTE_AWS_PUBLICKEY"))
		if key == "" {
			return fmt.Errorf("GIT_REMOTE_AWS_PUBLICKEY must be set to initialize .publickeys")
		}
		if err := os.WriteFile(publicKeysPath, []byte(key+"\n"), 0644); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(""), 0644); err != nil {
				return err
			}
		}
	}
	_, err := runGit(backupDir, "remote", "add", "origin", config.GitRemote)
	if err != nil {
		if !strings.Contains(err.Error(), "remote origin already exists") {
			return err
		}
	}
	err = gitAdd(backupDir, "ignore", "index.tsv", "objects.tsv", "packs.tsv", ".publickeys")
	if err != nil {
		return err
	}
	if !gitHasHead(backupDir) {
		return gitCommit(backupDir, []string{"init"})
	}
	return nil
}

func Add(config Config) error {
	if err := ensureRepoInitialized(config); err != nil {
		return err
	}
	lock, err := AcquireLock(config.Root)
	if err != nil {
		return err
	}
	defer lock.Release()

	backupDir := config.BackupDir()
	ignorePath := filepath.Join(backupDir, "ignore")
	ignore, err := LoadIgnore(ignorePath)
	if err != nil {
		return err
	}

	err = RemoveStaging(config.Root)
	if err != nil {
		return err
	}

	result, err := ScanRoot(config.Root, ignore)
	if err != nil {
		return err
	}

	objectsPath := filepath.Join(backupDir, "objects.tsv")
	objectsEntries, err := ReadObjects(objectsPath)
	if err != nil {
		return err
	}
	known := map[string]string{}
	for _, entry := range objectsEntries {
		known[entry.Hash] = entry.PackKey
	}

	var newFiles []FileHash
	for _, file := range result.Files {
		if _, ok := known[file.Hash]; !ok {
			newFiles = append(newFiles, file)
		}
	}
	sort.Slice(newFiles, func(i, j int) bool {
		return newFiles[i].Hash < newFiles[j].Hash
	})

	var packs []StagedPack
	if len(newFiles) != 0 {
		publicKeys, err := LoadPublicKeys(filepath.Join(backupDir, ".publickeys"))
		if err != nil {
			return err
		}
		commitCount, err := gitRevCount(backupDir)
		if err != nil {
			return err
		}
		createdUTC := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		chunk := int64(0)
		var current []FileHash
		var currentSize int64
		flush := func() error {
			if len(current) == 0 {
				return nil
			}
			packName := fmt.Sprintf("%010d.%s.tar.zst.enc.%05d", commitCount, createdUTC, chunk)
			chunk += 1
			pack, err := CreatePack(config.Root, packName, current, publicKeys, createdUTC)
			if err != nil {
				return err
			}
			pack.PackKey = ObjectKey(config.S3Prefix, packName)
			packs = append(packs, pack)
			current = nil
			currentSize = 0
			return nil
		}

		for _, file := range newFiles {
			if currentSize > 0 && currentSize+file.Size > config.ChunkSizeBytes {
				if err := flush(); err != nil {
					return err
				}
			}
			current = append(current, file)
			currentSize += file.Size
		}
		if err := flush(); err != nil {
			return err
		}
	}

	manifest := StagingManifest{Packs: packs}
	if err := WriteStaging(config.Root, manifest); err != nil {
		return err
	}

	indexPath := filepath.Join(backupDir, "index.tsv")
	if err := WriteIndex(indexPath, result.Entries); err != nil {
		return err
	}
	return gitAdd(backupDir, "index.tsv")
}

func Diff(config Config) ([]IndexDiff, error) {
	if err := ensureRepoInitialized(config); err != nil {
		return nil, err
	}
	backupDir := config.BackupDir()
	currentEntries, err := ReadIndex(filepath.Join(backupDir, "index.tsv"))
	if err != nil {
		return nil, err
	}
	oldEntries, err := ParseIndexFromGit(backupDir, "HEAD")
	if err != nil {
		return nil, err
	}
	oldByPath := IndexEntriesByPath(oldEntries)
	newByPath := IndexEntriesByPath(currentEntries)
	var diffs []IndexDiff
	for path, entry := range newByPath {
		old, ok := oldByPath[path]
		if !ok {
			diffs = append(diffs, IndexDiff{Kind: DiffAddition, New: entry})
			continue
		}
		if entry != old {
			diffs = append(diffs, IndexDiff{Kind: DiffChange, New: entry, Old: old})
		}
	}
	for path, entry := range oldByPath {
		if _, ok := newByPath[path]; ok {
			continue
		}
		diffs = append(diffs, IndexDiff{Kind: DiffDeletion, Old: entry})
	}
	sort.Slice(diffs, func(i, j int) bool {
		left := diffs[i]
		right := diffs[j]
		leftPath := left.New.Path
		if leftPath == "" {
			leftPath = left.Old.Path
		}
		rightPath := right.New.Path
		if rightPath == "" {
			rightPath = right.Old.Path
		}
		if leftPath == rightPath {
			return left.Kind < right.Kind
		}
		return leftPath < rightPath
	})
	return diffs, nil
}

func Commit(config Config) error {
	if err := ensureRepoInitialized(config); err != nil {
		return err
	}
	lock, err := AcquireLock(config.Root)
	if err != nil {
		return err
	}
	defer lock.Release()

	manifest, err := ReadStaging(config.Root)
	if err != nil {
		return err
	}
	backupDir := config.BackupDir()
	objectsPath := filepath.Join(backupDir, "objects.tsv")
	packsPath := filepath.Join(backupDir, "packs.tsv")
	objectsEntries, err := ReadObjects(objectsPath)
	if err != nil {
		return err
	}
	packsEntries, err := ReadPacks(packsPath)
	if err != nil {
		return err
	}

	client, err := NewS3Client(config)
	if err != nil {
		return err
	}

	ctx := context.Background()
	for _, pack := range manifest.Packs {
		file, err := os.Open(pack.Path)
		if err != nil {
			return err
		}
		_, _, err = client.PutObject(ctx, config.S3Bucket, pack.PackKey, file)
		_ = file.Close()
		if err != nil {
			return err
		}
		packsEntries = append(packsEntries, PackEntry{
			PackKey:    pack.PackKey,
			CipherHash: pack.CipherHash,
			CipherSize: pack.CipherSize,
			CreatedUTC: pack.CreatedUTC,
		})
		for _, hash := range pack.Hashes {
			objectsEntries = append(objectsEntries, ObjectEntry{Hash: hash, PackKey: pack.PackKey})
		}
	}

	SortObjects(objectsEntries)
	SortPacks(packsEntries)
	if err := WriteObjects(objectsPath, objectsEntries); err != nil {
		return err
	}
	if err := WritePacks(packsPath, packsEntries); err != nil {
		return err
	}
	if err := gitAdd(backupDir, "index.tsv", "objects.tsv", "packs.tsv"); err != nil {
		return err
	}
	messages := []string{"index-only-update"}
	if len(manifest.Packs) != 0 {
		messages = nil
		for _, pack := range manifest.Packs {
			messages = append(messages, fmt.Sprintf("%s %s %d", pack.PackKey, pack.CipherHash, pack.CipherSize))
		}
	}
	err = gitCommit(backupDir, messages)
	if err != nil {
		return err
	}
	err = gitPush(backupDir)
	if err != nil {
		return err
	}
	return RemoveStaging(config.Root)
}

func Find(config Config, regex string, revision string) ([]IndexEntry, error) {
	if err := ensureRepoCloned(config); err != nil {
		return nil, err
	}
	backupDir := config.BackupDir()
	if revision == "" {
		revision = "HEAD"
	}
	re, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	entries, err := ParseIndexFromGit(backupDir, revision)
	if err != nil {
		return nil, err
	}
	var matches []IndexEntry
	for _, entry := range entries {
		if re.MatchString(entry.Path) {
			matches = append(matches, entry)
		}
	}
	return matches, nil
}

func Restore(config Config, regex string, revision string, dryRun bool) ([]string, error) {
	backupDir := config.BackupDir()
	if revision == "" {
		revision = "HEAD"
	}
	entries, err := Find(config, regex, revision)
	if err != nil {
		return nil, err
	}
	allEntries, err := ParseIndexFromGit(backupDir, revision)
	if err != nil {
		return nil, err
	}
	entriesByPath := IndexEntriesByPath(allEntries)
	expanded := make([]IndexEntry, 0, len(entries))
	seen := map[string]bool{}
	queue := append([]IndexEntry{}, entries...)
	for len(queue) > 0 {
		entry := queue[0]
		queue = queue[1:]
		if seen[entry.Path] {
			continue
		}
		seen[entry.Path] = true
		expanded = append(expanded, entry)
		if entry.Kind != "symlink" {
			continue
		}
		targetPath := strings.TrimPrefix(entry.Ref, "target:")
		targetEntry, ok := entriesByPath[targetPath]
		if !ok {
			continue
		}
		if seen[targetEntry.Path] {
			continue
		}
		queue = append(queue, targetEntry)
	}
	entries = expanded
	objects, err := ParseObjectsFromGit(backupDir, revision)
	if err != nil {
		return nil, err
	}
	packs, err := ParsePacksFromGit(backupDir, revision)
	if err != nil {
		return nil, err
	}
	packMap := map[string]PackEntry{}
	for _, entry := range packs {
		packMap[entry.PackKey] = entry
	}
	objectMap := map[string]string{}
	for _, entry := range objects {
		objectMap[entry.Hash] = entry.PackKey
	}

	filesByHash := map[string][]IndexEntry{}
	var symlinks []IndexEntry
	for _, entry := range entries {
		switch entry.Kind {
		case "file":
			hash := strings.TrimPrefix(entry.Ref, "blake2b:")
			filesByHash[hash] = append(filesByHash[hash], entry)
		case "symlink":
			symlinks = append(symlinks, entry)
		default:
			return nil, fmt.Errorf("unknown entry kind: %s", entry.Kind)
		}
	}

	neededPacks := map[string][]string{}
	for hash := range filesByHash {
		packKey, ok := objectMap[hash]
		if !ok {
			return nil, fmt.Errorf("missing pack for hash %s", hash)
		}
		neededPacks[packKey] = append(neededPacks[packKey], hash)
	}

	client, err := NewS3Client(config)
	if err != nil {
		return nil, err
	}

	var outputs []string
	ctx := context.Background()
	secretKey, err := LoadSecretKey()
	if err != nil {
		return nil, err
	}
	for packKey, hashes := range neededPacks {
		packEntry, ok := packMap[packKey]
		if !ok {
			return nil, fmt.Errorf("missing pack metadata for %s", packKey)
		}
		body, err := client.GetObject(ctx, config.S3Bucket, packKey)
		if err != nil {
			return nil, err
		}
		hash, err := blake2b.New512(nil)
		if err != nil {
			return nil, err
		}
		counting := &CountWriter{Writer: hash}
		teeReader := io.TeeReader(body, counting)
		plainReader, plainWriter := io.Pipe()
		decryptErr := make(chan error, 1)
		go func() {
			defer func() {
				if value := recover(); value != nil {
					decryptErr <- fmt.Errorf("decrypt panic: %v", value)
				}
			}()
			err := libsodium.StreamDecryptRecipients(secretKey, teeReader, plainWriter)
			_ = plainWriter.Close()
			decryptErr <- err
		}()
		zstdReader, err := zstd.NewReader(plainReader)
		if err != nil {
			return nil, err
		}
		tarReader := tar.NewReader(zstdReader)
		hashSet := map[string]bool{}
		for _, hash := range hashes {
			hashSet[hash] = true
		}
		found := map[string]bool{}
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if !hashSet[header.Name] {
				_, err := io.Copy(io.Discard, tarReader)
				if err != nil {
					return nil, err
				}
				continue
			}
			found[header.Name] = true
			entries := filesByHash[header.Name]
			var writers []io.Writer
			var closers []io.Closer
			for _, entry := range entries {
				path, err := IndexPathToOS(config.Root, entry.Path)
				if err != nil {
					return nil, err
				}
				if dryRun {
					status := "new"
					if _, err := os.Stat(path); err == nil {
						status = "overwrite"
					}
					outputs = append(outputs, fmt.Sprintf("%s\t%s", status, entry.Path))
					continue
				}
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return nil, err
				}
				file, err := os.Create(path)
				if err != nil {
					return nil, err
				}
				writers = append(writers, file)
				closers = append(closers, file)
				outputs = append(outputs, fmt.Sprintf("%s\t%s", entry.Path, header.Name))
			}
			if dryRun {
				_, err := io.Copy(io.Discard, tarReader)
				if err != nil {
					return nil, err
				}
				continue
			}
			_, err = io.Copy(io.MultiWriter(writers...), tarReader)
			for _, closer := range closers {
				_ = closer.Close()
			}
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				path, err := IndexPathToOS(config.Root, entry.Path)
				if err != nil {
					return nil, err
				}
				mode, err := parseFileMode(entry.Mode)
				if err != nil {
					return nil, err
				}
				err = os.Chmod(path, mode)
				if err != nil {
					return nil, err
				}
			}
		}
		zstdReader.Close()
		err = <-decryptErr
		if err != nil {
			return nil, err
		}
		_ = body.Close()
		for _, needed := range hashes {
			if !found[needed] {
				return nil, fmt.Errorf("pack %s did not contain required hash %s", packKey, needed)
			}
		}
		cipherHash := fmt.Sprintf("%x", hash.Sum(nil))
		if cipherHash != packEntry.CipherHash {
			return nil, fmt.Errorf("cipher hash mismatch for %s", packKey)
		}
		if counting.Count != packEntry.CipherSize {
			return nil, fmt.Errorf("cipher size mismatch for %s", packKey)
		}
	}

	for _, entry := range symlinks {
		path, err := IndexPathToOS(config.Root, entry.Path)
		if err != nil {
			return nil, err
		}
		if dryRun {
			status := "new"
			if _, err := os.Lstat(path); err == nil {
				status = "overwrite"
			}
			outputs = append(outputs, fmt.Sprintf("%s\t%s", status, entry.Path))
			continue
		}
		targetPath := strings.TrimPrefix(entry.Ref, "target:")
		targetOS, err := IndexPathToOS(config.Root, targetPath)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(filepath.Dir(path), targetOS)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
		_ = os.Remove(path)
		if err := os.Symlink(rel, path); err != nil {
			return nil, err
		}
		outputs = append(outputs, fmt.Sprintf("%s\t%s", entry.Path, targetPath))
	}

	return outputs, nil
}

func Reset(config Config) error {
	if err := ensureRepoInitialized(config); err != nil {
		return err
	}
	lock, err := AcquireLock(config.Root)
	if err != nil {
		return err
	}
	defer lock.Release()
	backupDir := config.BackupDir()
	tracked, err := gitListFiles(backupDir)
	if err != nil {
		return err
	}
	if gitHasHead(backupDir) {
		for _, file := range tracked {
			data, err := ParseTSVFromGit(backupDir, "HEAD", file)
			if err != nil {
				return err
			}
			path := filepath.Join(backupDir, file)
			if err := os.WriteFile(path, data, 0644); err != nil {
				return err
			}
		}
	} else {
		for _, file := range tracked {
			path := filepath.Join(backupDir, file)
			err := os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	if err := gitAdd(backupDir, tracked...); err != nil {
		return err
	}
	return RemoveStaging(config.Root)
}

func parseFileMode(mode string) (os.FileMode, error) {
	if mode == "-" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(parsed), nil
}
