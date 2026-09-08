package backup

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/repository"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

func TestRestorePlanningHasBoundedRSS(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("large bounded-memory acceptance test")
	}
	const records = 500_000
	metadata := t.TempDir()
	writeLargeRestoreMetadata(t, metadata, records)
	stage := t.TempDir()
	target := t.TempDir()
	resultPath := filepath.Join(t.TempDir(), "result")
	command := exec.Command(os.Args[0], "-test.run=^TestRestorePlanningRSSHelper$")
	command.Env = append(os.Environ(),
		"BACKUP_RESTORE_RSS_METADATA="+metadata,
		"BACKUP_RESTORE_RSS_STAGE="+stage,
		"BACKUP_RESTORE_RSS_TARGET="+target,
		"BACKUP_RESTORE_RSS_RESULT="+resultPath,
		"BACKUP_RESTORE_RSS_RECORDS="+strconv.Itoa(records),
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restore-planning subprocess: %v\n%s", err, output)
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	resultText := strings.TrimSpace(string(data))
	fields := strings.Fields(resultText)
	if len(fields) != 2 {
		t.Fatalf("invalid RSS result %q", resultText)
	}
	maximumRSSKiB, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("planning %d selected paths used %d KiB maximum RSS for %s bytes of source metadata", records, maximumRSSKiB, fields[1])
	if maximumRSSKiB > 160<<10 {
		t.Fatalf("planning %d selected paths used %d KiB maximum RSS", records, maximumRSSKiB)
	}
}

func TestRestorePlanningRSSHelper(t *testing.T) {
	metadata := os.Getenv("BACKUP_RESTORE_RSS_METADATA")
	if metadata == "" {
		t.Skip("subprocess helper")
	}
	records, err := strconv.ParseUint(os.Getenv("BACKUP_RESTORE_RSS_RECORDS"), 10, 64)
	if err != nil || records == 0 {
		t.Fatal("invalid expected record count")
	}
	state, err := repository.ParseFileState(restoreBlobFiles(t, metadata), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	targetFD, _, err := openTargetRoot(os.Getenv("BACKUP_RESTORE_RSS_TARGET"))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(targetFD)
	var result RestoreResult
	var reported uint64
	_, conflicts, err := planRestoreSelection(state, regexp.MustCompile(`^\./item-`), targetFD, false, os.Getenv("BACKUP_RESTORE_RSS_STAGE"), func(event RestoreEvent) error {
		if event.Kind == RestorePlanned {
			reported++
		}
		return nil
	}, &result)
	if err != nil {
		t.Fatal(err)
	}
	if conflicts || result.Planned != records || reported != records {
		t.Fatalf("planned=%d reported=%d conflicts=%t", result.Planned, reported, conflicts)
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	metadataInfo, err := os.Stat(filepath.Join(metadata, "index.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	resultData := fmt.Sprintf("%d %d\n", usage.Maxrss, metadataInfo.Size())
	if err := os.WriteFile(os.Getenv("BACKUP_RESTORE_RSS_RESULT"), []byte(resultData), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreReportFailureCountsEveryUnpublishedPath(t *testing.T) {
	stage := t.TempDir()
	regular := filepath.Join(stage, "regular.index")
	symlinks := filepath.Join(stage, "symlinks.index")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []format.IndexEntry{
		{Path: "./a", Kind: format.KindSymlink, Ref: "target:./"},
		{Path: "./b", Kind: format.KindSymlink, Ref: "target:./"},
		{Path: "./c", Kind: format.KindSymlink, Ref: "target:./"},
	}
	data, err := format.MarshalIndex(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symlinks, data, 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	targetFD, targetPath, err := openTargetRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(targetFD)
	reportErr := errors.New("report output failed")
	var result RestoreResult
	err = publishRestoreSelection(targetFD, targetPath, restoreSelection{directory: stage, regularIndex: regular, symlinkIndex: symlinks}, false, func(event RestoreEvent) error {
		if event.Kind == RestorePublished {
			return reportErr
		}
		return nil
	}, &result)
	if !errors.Is(err, reportErr) || result.Published != 1 || result.Remaining != 2 {
		t.Fatalf("err=%v published=%d remaining=%d", err, result.Published, result.Remaining)
	}
	if _, err := os.Lstat(filepath.Join(target, "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path b was published after report failure: %v", err)
	}
}

func writeLargeRestoreMetadata(t *testing.T, directory string, records int) {
	t.Helper()
	key := make([]byte, 32)
	repositoryFormat := format.NewRepositoryFormat("123e4567-e89b-42d3-a456-426614174000", "11111111111111111111111111111111", format.RecoveryFingerprint(key))
	formatBytes, err := repositoryFormat.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	publicKeys, err := format.MarshalPublicKeys([][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	mirrors, err := format.MarshalMirrors([]format.Mirror{{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: "https://localhost:8443", Region: "us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"FORMAT": formatBytes, "objects.tsv": nil, "packs.tsv": nil, "ignore": nil,
		".publickeys": publicKeys, "mirrors.tsv": mirrors,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	index, err := os.OpenFile(filepath.Join(directory, "index.tsv"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriterSize(index, 1<<20)
	for number := 0; number < records; number++ {
		if _, err := fmt.Fprintf(writer, "./item-%07d\tsymlink\ttarget:./\t0\t-\t-\n", number); err != nil {
			index.Close()
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		index.Close()
		t.Fatal(err)
	}
	if err := index.Sync(); err != nil {
		index.Close()
		t.Fatal(err)
	}
	if err := index.Close(); err != nil {
		t.Fatal(err)
	}
}

func restoreBlobFiles(t *testing.T, directory string) map[string]repository.BlobFile {
	t.Helper()
	files := make(map[string]repository.BlobFile, len(repository.RequiredBlobNames))
	for _, name := range repository.RequiredBlobNames {
		path := filepath.Join(directory, name)
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		hash, _ := blake2b.New512(nil)
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("hash %s: copy=%v close=%v", name, copyErr, closeErr)
		}
		files[name] = repository.BlobFile{Path: path, Size: uint64(size), BLAKE2b: hex.EncodeToString(hash.Sum(nil))}
	}
	return files
}
