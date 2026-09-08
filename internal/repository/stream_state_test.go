package repository

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

func TestFileStateRejectsCrossCatalogViolations(t *testing.T) {
	fileEntry := format.IndexEntry{Path: "./a", Kind: format.KindFile, Ref: "blake2b:" + plainHash, Size: 3, Mode: 0o600}
	object := format.ObjectEntry{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}
	packEntry := format.PackEntry{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}

	ancestorIndex, err := format.MarshalIndexEntry(fileEntry)
	if err != nil {
		t.Fatal(err)
	}
	descendant := fileEntry
	descendant.Path = "./a/b"
	descendantRow, err := format.MarshalIndexEntry(descendant)
	if err != nil {
		t.Fatal(err)
	}
	ancestorIndex = append(ancestorIndex, descendantRow...)

	tests := []struct {
		name    string
		index   []byte
		objects []byte
		packs   []byte
		want    string
	}{
		{
			name: "ancestor leaf", index: ancestorIndex,
			objects: mustObjects(t, []format.ObjectEntry{object}), packs: mustPacks(t, []format.PackEntry{packEntry}),
			want: "ancestor",
		},
		{
			name: "missing object", index: mustIndex(t, []format.IndexEntry{fileEntry}),
			objects: nil, packs: nil, want: "missing object",
		},
		{
			name: "missing pack", index: mustIndex(t, []format.IndexEntry{fileEntry}),
			objects: mustObjects(t, []format.ObjectEntry{object}), packs: nil, want: "missing pack",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blobs := validGenesisBlobs(t)
			blobs["index.tsv"], blobs["objects.tsv"], blobs["packs.tsv"] = test.index, test.objects, test.packs
			_, err := ParseFileState(writeBlobFiles(t, blobs), format.DefaultLimits())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestFileStateTransitionsStreamCumulativeCatalogs(t *testing.T) {
	baseObject := format.ObjectEntry{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}
	basePack := format.PackEntry{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}
	baseBlobs := validGenesisBlobs(t)
	baseBlobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{baseObject})
	baseBlobs["packs.tsv"] = mustPacks(t, []format.PackEntry{basePack})
	base := parseFileState(t, baseBlobs)

	secondPlain := strings.Repeat("f", 128)
	secondPackHash := strings.Repeat("f", 127) + "e"
	secondObject := format.ObjectEntry{PlaintextHash: secondPlain, PlaintextSize: 4, PackHash: secondPackHash}
	secondPack := format.PackEntry{
		PackHash: secondPackHash, PartCount: 1, PartHash: strings.Repeat("f", 126) + "ed",
		PartSHA256: strings.Repeat("f", 64), PartMD5: strings.Repeat("f", 32), PartSize: 11,
		ObjectID: "22222222222222222222222222222222",
	}
	extensionBlobs := cloneBlobs(baseBlobs)
	extensionBlobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{baseObject, secondObject})
	extensionBlobs["packs.tsv"] = mustPacks(t, []format.PackEntry{basePack, secondPack})
	extension := parseFileState(t, extensionBlobs)
	kind, err := ValidateTransition(base, extension)
	if err != nil || kind != TransitionOrdinary {
		t.Fatalf("streamed ordinary extension: kind=%v err=%v", kind, err)
	}
	var changed []format.PackEntry
	if err := WalkChangedPacks(base, extension, kind, func(entry format.PackEntry) error {
		changed = append(changed, entry)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != secondPack {
		t.Fatalf("changed packs=%#v", changed)
	}

	repairBlobs := cloneBlobs(baseBlobs)
	relocated := basePack
	relocated.ObjectID = "33333333333333333333333333333333"
	repairBlobs["packs.tsv"] = mustPacks(t, []format.PackEntry{relocated})
	repair := parseFileState(t, repairBlobs)
	kind, err = ValidateTransition(base, repair)
	if err != nil || kind != TransitionRepair {
		t.Fatalf("streamed repair: kind=%v err=%v", kind, err)
	}

	tests := []struct {
		name   string
		mutate func(map[string][]byte)
		want   string
	}{
		{
			name: "altered object row",
			mutate: func(blobs map[string][]byte) {
				altered := baseObject
				altered.PlaintextSize++
				blobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{altered})
			},
			want: "altered object row",
		},
		{
			name: "removed cumulative rows",
			mutate: func(blobs map[string][]byte) {
				blobs["objects.tsv"] = nil
				blobs["packs.tsv"] = nil
			},
			want: "removed object rows",
		},
		{
			name: "altered pack row",
			mutate: func(blobs map[string][]byte) {
				altered := basePack
				altered.PartSize++
				blobs["packs.tsv"] = mustPacks(t, []format.PackEntry{altered})
			},
			want: "logical pack field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			blobs := cloneBlobs(baseBlobs)
			test.mutate(blobs)
			candidate := parseFileState(t, blobs)
			_, err := ValidateTransition(base, candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestFileStateDetectsCandidateByteMutation(t *testing.T) {
	blobs := validGenesisBlobs(t)
	blobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}})
	blobs["packs.tsv"] = mustPacks(t, []format.PackEntry{{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}})
	files := writeBlobFiles(t, blobs)
	state, err := ParseFileState(files, format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	path := files["objects.tsv"].Path
	mutated := strings.Replace(string(blobs["objects.tsv"]), "\t3\t", "\t4\t", 1)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := state.WalkObjects(format.DefaultLimits(), nil); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("mutated candidate bytes were accepted: %v", err)
	}
}

func TestFileStateLargeCatalogHasBoundedRSS(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("large bounded-memory acceptance test")
	}
	const records = 250_000
	directory := t.TempDir()
	catalogBytes := writeLargeFileState(t, directory, records)
	if catalogBytes < 150<<20 {
		t.Fatalf("large-catalog fixture is only %d bytes", catalogBytes)
	}
	rssPath := filepath.Join(t.TempDir(), "rss")
	command := exec.Command(os.Args[0], "-test.run=^TestFileStateLargeCatalogRSSHelper$")
	command.Env = append(os.Environ(), "BACKUP_RSS_STATE="+directory, "BACKUP_RSS_RESULT="+rssPath, "BACKUP_RSS_RECORDS="+strconv.Itoa(records))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("large-catalog subprocess: %v\n%s", err, output)
	}
	data, err := os.ReadFile(rssPath)
	if err != nil {
		t.Fatal(err)
	}
	maximumRSSKiB, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("validated %d bytes of cumulative catalogs at %d KiB maximum RSS", catalogBytes, maximumRSSKiB)
	// The catalogs alone exceed 150 MiB. A row-retaining implementation needs
	// several times that much heap; the streaming validator normally peaks well
	// below this deliberately conservative process-RSS ceiling.
	if maximumRSSKiB > 128<<10 {
		t.Fatalf("large-catalog validation used %d KiB maximum RSS", maximumRSSKiB)
	}
}

func TestFileStateLargeCatalogRSSHelper(t *testing.T) {
	directory := os.Getenv("BACKUP_RSS_STATE")
	if directory == "" {
		t.Skip("subprocess helper")
	}
	records, err := strconv.Atoi(os.Getenv("BACKUP_RSS_RECORDS"))
	if err != nil || records <= 0 {
		t.Fatalf("invalid expected record count")
	}
	state, err := ParseFileState(blobFilesFromDirectory(t, directory), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if state.ObjectCount != uint64(records) || state.PackCount != uint64(records) || state.IndexCount != 0 {
		t.Fatalf("catalog counts index=%d objects=%d packs=%d", state.IndexCount, state.ObjectCount, state.PackCount)
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("BACKUP_RSS_RESULT"), []byte(strconv.FormatInt(usage.Maxrss, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func parseFileState(t *testing.T, blobs map[string][]byte) State {
	t.Helper()
	state, err := ParseFileState(writeBlobFiles(t, blobs), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func writeBlobFiles(t *testing.T, blobs map[string][]byte) map[string]BlobFile {
	t.Helper()
	directory := t.TempDir()
	files := make(map[string]BlobFile, len(blobs))
	for name, data := range blobs {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := blake2b.Sum512(data)
		files[name] = BlobFile{Path: path, Size: uint64(len(data)), BLAKE2b: hex.EncodeToString(digest[:])}
	}
	return files
}

func blobFilesFromDirectory(t *testing.T, directory string) map[string]BlobFile {
	t.Helper()
	files := make(map[string]BlobFile, len(RequiredBlobNames))
	for _, name := range RequiredBlobNames {
		path := filepath.Join(directory, name)
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		hash, err := blake2b.New512(nil)
		if err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("hash %s: copy=%v close=%v", name, copyErr, closeErr)
		}
		files[name] = BlobFile{Path: path, Size: uint64(size), BLAKE2b: hex.EncodeToString(hash.Sum(nil))}
	}
	return files
}

func writeLargeFileState(t *testing.T, directory string, records int) int64 {
	t.Helper()
	blobs := validGenesisBlobs(t)
	for name, data := range blobs {
		if name == "objects.tsv" || name == "packs.tsv" {
			continue
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	objects, err := os.OpenFile(filepath.Join(directory, "objects.tsv"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	packs, err := os.OpenFile(filepath.Join(directory, "packs.tsv"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = objects.Close()
		t.Fatal(err)
	}
	objectWriter := bufio.NewWriterSize(objects, 1<<20)
	packWriter := bufio.NewWriterSize(packs, 1<<20)
	for index := 0; index < records; index++ {
		hash := fmt.Sprintf("%0128x", index)
		sha := fmt.Sprintf("%064x", index)
		short := fmt.Sprintf("%032x", index)
		if _, err := fmt.Fprintf(objectWriter, "%s\t1\t%s\n", hash, hash); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(packWriter, "%s\t0\t1\t%s\t%s\t%s\t1\t%s\n", hash, hash, sha, short, short); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		writer *bufio.Writer
		file   *os.File
	}{{objectWriter, objects}, {packWriter, packs}} {
		if err := item.writer.Flush(); err != nil {
			t.Fatal(err)
		}
		if err := item.file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := item.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	objectInfo, err := os.Stat(filepath.Join(directory, "objects.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	packInfo, err := os.Stat(filepath.Join(directory, "packs.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	return objectInfo.Size() + packInfo.Size()
}
