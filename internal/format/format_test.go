package format

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	hashA   = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	hashB   = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	shaA    = "2222222222222222222222222222222222222222222222222222222222222222"
	md5A    = "33333333333333333333333333333333"
	idA     = "44444444444444444444444444444444"
	commitA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestFormatRoundTripAndExactKeys(t *testing.T) {
	f := NewRepositoryFormat(
		"123e4567-e89b-42d3-a456-426614174000",
		"v1:blake2b-512:"+hashA,
	)
	data, err := f.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	want := "checksum-algorithms\tblake2b-512,sha256,md5\n" +
		"compression-algorithm\tzstd\n" +
		"content-hash-algorithm\tblake2b-512\n" +
		"encryption-algorithm\tgo-libsodium-recipient-stream-v1\n" +
		"format-version\t1\n" +
		"git-object-format\tsha256\n" +
		"pack-format-version\t1\n" +
		"pack-hash-algorithm\tblake2b-512\n" +
		"recovery-recipient-fingerprint\tv1:blake2b-512:" + hashA + "\n" +
		"repository-uuid\t123e4567-e89b-42d3-a456-426614174000\n" +
		"tar-algorithm\tposix-pax-go-archive-tar-v1\n"
	if string(data) != want {
		t.Fatalf("unexpected FORMAT:\n%s", data)
	}
	got, err := ParseRepositoryFormat(bytes.NewReader(data), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got != f {
		t.Fatalf("round trip mismatch: %#v != %#v", got, f)
	}
	for _, mutation := range []string{
		strings.Replace(want, "format-version\t1\n", "", 1),
		want + "unknown\tvalue\n",
		strings.Replace(want, "pack-format-version\t1\n", "object-namespace\t55555555555555555555555555555555\npack-format-version\t1\n", 1),
		strings.Replace(want, "zstd", "gzip", 1),
		strings.Replace(want, "checksum-algorithms", "tar-algorithm", 1),
	} {
		if _, err := ParseRepositoryFormat(strings.NewReader(mutation), DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid FORMAT:\n%s", mutation)
		}
	}
}

func TestCanonicalTablesGoldenRoundTrip(t *testing.T) {
	index := []IndexEntry{
		{Path: "./file with space", Kind: KindFile, Ref: "blake2b:" + hashA, Size: 5, Mode: 0, MtimeNS: -1},
		{Path: "./link", Kind: KindSymlink, Ref: "target:./target", Size: 0},
		{Path: "./root-link", Kind: KindSymlink, Ref: "target:./", Size: 0},
	}
	indexBytes, err := MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	wantIndex := "./file with space\tfile\tblake2b:" + hashA + "\t5\t0000\t-1\n" +
		"./link\tsymlink\ttarget:./target\t0\t-\t-\n" +
		"./root-link\tsymlink\ttarget:./\t0\t-\t-\n"
	if string(indexBytes) != wantIndex {
		t.Fatalf("index golden mismatch:\n%s", indexBytes)
	}
	parsedIndex, err := ParseIndex(bytes.NewReader(indexBytes), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedIndex) != len(index) {
		t.Fatalf("index round trip length mismatch: %#v", parsedIndex)
	}
	for position := range index {
		if parsedIndex[position] != index[position] {
			t.Fatalf("index round trip mismatch at %d: %#v != %#v", position, parsedIndex[position], index[position])
		}
	}

	objects := []ObjectEntry{{PlaintextHash: hashA, PlaintextSize: 5, PackHash: hashB}}
	objectBytes, err := MarshalObjects(objects)
	if err != nil {
		t.Fatal(err)
	}
	if string(objectBytes) != hashA+"\t5\t"+hashB+"\n" {
		t.Fatalf("objects golden mismatch: %q", objectBytes)
	}
	if _, err := ParseObjects(bytes.NewReader(objectBytes), DefaultLimits()); err != nil {
		t.Fatal(err)
	}

	packs := []PackEntry{{
		PackHash: hashB, PartNumber: 0, PartCount: 1, PartHash: hashA,
		PartSHA256: shaA, PartMD5: md5A, PartSize: 9, ObjectID: idA,
	}}
	packBytes, err := MarshalPacks(packs)
	if err != nil {
		t.Fatal(err)
	}
	wantPack := hashB + "\t0\t1\t" + hashA + "\t" + shaA + "\t" + md5A + "\t9\t" + idA + "\n"
	if string(packBytes) != wantPack {
		t.Fatalf("packs golden mismatch: %q", packBytes)
	}
	if _, err := ParsePacks(bytes.NewReader(packBytes), DefaultLimits()); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataManifestJSONRoundTripForDurableState(t *testing.T) {
	manifest := MetadataManifest{
		RepositoryUUID: "123e4567-e89b-42d3-a456-426614174000",
		Sequence:       0,
		BaseCommit:     "-",
		TipCommit:      commitA,
		Kind:           BundleFull,
		BundleHash:     hashB,
		BundleSize:     9,
		Parts: []ManifestPart{{
			Number: 0, Count: 1, ObjectID: idA, Hash: hashA, SHA256: shaA, MD5: md5A, Size: 9,
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded MetadataManifest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RepositoryUUID != manifest.RepositoryUUID || decoded.Sequence != manifest.Sequence || decoded.BaseCommit != manifest.BaseCommit || decoded.TipCommit != manifest.TipCommit || decoded.Kind != manifest.Kind || decoded.BundleHash != manifest.BundleHash || decoded.BundleSize != manifest.BundleSize || len(decoded.Parts) != 1 || decoded.Parts[0] != manifest.Parts[0] {
		t.Fatalf("manifest JSON round trip mismatch: %#v != %#v", decoded, manifest)
	}
}

func TestCanonicalParserRejectsNoncanonicalInput(t *testing.T) {
	valid := "./a\tfile\tblake2b:" + hashA + "\t0\t0644\t0\n"
	tests := map[string]string{
		"missing final newline": strings.TrimSuffix(valid, "\n"),
		"crlf":                  strings.ReplaceAll(valid, "\n", "\r\n"),
		"bom":                   "\ufeff" + valid,
		"quoted":                "\"./a\"\tfile\tblake2b:" + hashA + "\t0\t0644\t0\n",
		"leading zero size":     strings.Replace(valid, "\t0\t0644", "\t00\t0644", 1),
		"three digit mode":      strings.Replace(valid, "0644", "644", 1),
		"uppercase hash":        strings.Replace(valid, hashA, strings.ToUpper(strings.Replace(hashA, "0", "A", 1)), 1),
		"extra field":           strings.TrimSuffix(valid, "\n") + "\tx\n",
		"empty row":             valid + "\n",
		"nul":                   strings.Replace(valid, "./a", "./a\x00", 1),
		"noncanonical path":     strings.Replace(valid, "./a", "./x/../a", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseIndex(strings.NewReader(input), DefaultLimits()); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestTableOrderUniquenessAndAncestors(t *testing.T) {
	row := func(path string, hash string) string {
		return path + "\tfile\tblake2b:" + hash + "\t0\t0644\t0\n"
	}
	for _, input := range []string{
		row("./b", hashA) + row("./a", hashB),
		row("./a", hashA) + row("./a", hashB),
		row("./a", hashA) + row("./a/b", hashB),
		row("./a", hashA) + row("./a-", hashB) + row("./a/b", strings.Repeat("2", 128)),
	} {
		if _, err := ParseIndex(strings.NewReader(input), DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid ordering/topology:\n%s", input)
		}
	}
}

func TestPacksRequireContiguousCompleteParts(t *testing.T) {
	row := func(n, count int, id string) string {
		return hashB + "\t" + itoa(n) + "\t" + itoa(count) + "\t" + hashA + "\t" + shaA + "\t" + md5A + "\t9\t" + id + "\n"
	}
	for _, input := range []string{
		row(1, 2, idA),
		row(0, 2, idA),
		row(0, 2, idA) + row(1, 3, "55555555555555555555555555555555"),
		row(0, 1, idA) + row(0, 1, "55555555555555555555555555555555"),
	} {
		if _, err := ParsePacks(strings.NewReader(input), DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid packs:\n%s", input)
		}
	}
}

func TestCiphertextPartsMustBeNonempty(t *testing.T) {
	pack := []PackEntry{{PackHash: hashB, PartCount: 1, PartHash: hashA, PartSHA256: shaA, PartMD5: md5A, PartSize: 0, ObjectID: idA}}
	if _, err := MarshalPacks(pack); err == nil {
		t.Fatal("zero-byte encrypted pack part was accepted")
	}
	manifest := MetadataManifest{
		RepositoryUUID: "123e4567-e89b-42d3-a456-426614174000",
		BaseCommit:     "-", TipCommit: commitA, Kind: BundleFull, BundleHash: hashB,
		Parts: []ManifestPart{{Number: 0, Count: 1, ObjectID: idA, Hash: hashA, SHA256: shaA, MD5: md5A}},
	}
	if _, err := manifest.MarshalText(); err == nil {
		t.Fatal("zero-byte encrypted metadata part was accepted")
	}
}

func TestCrossCatalogValidation(t *testing.T) {
	index := []IndexEntry{{Path: "./a", Kind: KindFile, Ref: "blake2b:" + hashA, Size: 5, Mode: 0o644}}
	objects := []ObjectEntry{{PlaintextHash: hashA, PlaintextSize: 5, PackHash: hashB}}
	packs := []PackEntry{{PackHash: hashB, PartCount: 1, PartHash: hashA, PartSHA256: shaA, PartMD5: md5A, PartSize: 1, ObjectID: idA}}
	if err := ValidateCatalogs(index, objects, packs); err != nil {
		t.Fatal(err)
	}
	bad := append([]ObjectEntry(nil), objects...)
	bad[0].PlaintextSize = 6
	if err := ValidateCatalogs(index, bad, packs); err == nil {
		t.Fatal("accepted inconsistent plaintext size")
	}
	if err := ValidateCatalogs(index, objects, nil); err == nil {
		t.Fatal("accepted missing pack")
	}
}

func TestIgnoreAndPublicKeysAreExact(t *testing.T) {
	ignore, err := ParseIgnore(strings.NewReader("^\\./proc(?:/|$)\nfoo bar\n\n#literal\n"), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !ignore.Match("./proc/x") || !ignore.Match("./foo bar") || !ignore.Match("./#literal") {
		t.Fatal("ignore expressions did not match")
	}
	for _, bad := range []string{"x", "[\n", "x\r\n", "x\x00\n"} {
		if _, err := ParseIgnore(strings.NewReader(bad), DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid ignore %q", bad)
		}
	}

	keyA := strings.Repeat("0", 64)
	keyB := strings.Repeat("1", 64)
	keys, err := ParsePublicKeys(strings.NewReader(keyA+"\n"+keyB+"\n"), DefaultLimits())
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys: %v %#v", err, keys)
	}
	fingerprint := RecoveryFingerprint(keys[0])
	if !strings.HasPrefix(fingerprint, "v1:blake2b-512:") {
		t.Fatalf("bad fingerprint %q", fingerprint)
	}
	for _, bad := range []string{keyA, keyA + "\n" + keyA + "\n", keyB + "\n" + keyA + "\n", strings.ToUpper("a"+keyA[1:]) + "\n", "\n"} {
		if _, err := ParsePublicKeys(strings.NewReader(bad), DefaultLimits()); err == nil {
			t.Fatalf("accepted invalid keys %q", bad)
		}
	}
}

func TestMirrorsAndManifestGolden(t *testing.T) {
	mirrors := []Mirror{{Name: "local", Kind: MirrorBackupServer, S3URL: "s3://bucket/prefix", Endpoint: "https://backup.example:8443", Region: "us-east-1"}}
	data, err := MarshalMirrors(mirrors)
	if err != nil {
		t.Fatal(err)
	}
	want := "local\tbackup-server\ts3://bucket/prefix\thttps://backup.example:8443\tus-east-1\n"
	if string(data) != want {
		t.Fatalf("mirror golden mismatch: %q", data)
	}
	if _, err := ParseMirrors(bytes.NewReader(data), DefaultLimits()); err != nil {
		t.Fatal(err)
	}

	manifest := MetadataManifest{
		RepositoryUUID: "123e4567-e89b-42d3-a456-426614174000",
		Sequence:       0, BaseCommit: "-", TipCommit: commitA, Kind: BundleFull,
		BundleHash: hashB, BundleSize: 10,
		Parts: []ManifestPart{{Number: 0, Count: 1, ObjectID: idA, Hash: hashA, SHA256: shaA, MD5: md5A, Size: 10}},
	}
	manifestData, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	wantManifest := "repository-uuid\t123e4567-e89b-42d3-a456-426614174000\n" +
		"manifest-format\t1\nsequence\t0\nbase-commit\t-\ntip-commit\t" + commitA + "\nkind\tfull\n" +
		"bundle-blake2b\t" + hashB + "\nbundle-size\t10\npart-count\t1\n" +
		"part\t0\t1\t" + idA + "\t" + hashA + "\t" + shaA + "\t" + md5A + "\t10\n"
	if string(manifestData) != wantManifest {
		t.Fatalf("manifest golden mismatch:\n%s", manifestData)
	}
	got, err := ParseMetadataManifest(bytes.NewReader(manifestData), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got.TipCommit != commitA || len(got.Parts) != 1 {
		t.Fatalf("manifest round trip mismatch: %#v", got)
	}
	manifest.Sequence = 37
	if _, err := manifest.MarshalText(); err == nil {
		t.Fatal("non-genesis full checkpoint was accepted")
	}
	manifest.Sequence = 0
	manifest.Parts = make([]ManifestPart, MaximumMetadataManifestParts+1)
	if _, err := manifest.MarshalText(); err == nil {
		t.Fatal("manifest with more parts than its wire-size ceiling was accepted")
	}
}

func TestBoundsApplyBeforeLargeRecordsAreAccepted(t *testing.T) {
	const row = "./a\tsymlink\ttarget:./x\t0\t-\t-\n"
	limits := DefaultLimits()
	limits.MaxLineBytes = len(row) - 1 // The LF is not part of the record.
	limits.MaxFieldBytes = limits.MaxLineBytes
	if err := limits.validate(); err != nil {
		t.Fatalf("invalid line-limit fixture: %v", err)
	}
	if entries, err := ParseIndex(strings.NewReader(row), limits); err != nil || len(entries) != 1 {
		t.Fatalf("record at the line limit rejected: %v", err)
	}
	longer := strings.Replace(row, "./a\t", "./aa\t", 1)
	if _, err := ParseIndex(strings.NewReader(longer), DefaultLimits()); err != nil {
		t.Fatalf("oversized fixture is not otherwise valid: %v", err)
	}
	if _, err := ParseIndex(strings.NewReader(longer), limits); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("expected line-length rejection, got %v", err)
	}
	limits = DefaultLimits()
	limits.MaxRecords = 1
	if entries, err := ParseIndex(strings.NewReader(row), limits); err != nil || len(entries) != 1 {
		t.Fatalf("record at the count limit rejected: %v", err)
	}
	input := row + strings.Replace(row, "./a\t", "./b\t", 1)
	if entries, err := ParseIndex(strings.NewReader(input), DefaultLimits()); err != nil || len(entries) != 2 {
		t.Fatalf("two-record fixture is not otherwise valid: %v", err)
	}
	if _, err := ParseIndex(strings.NewReader(input), limits); err == nil || err.Error() != "index.tsv: metadata exceeds 1 records" {
		t.Fatalf("expected record-count rejection, got %v", err)
	}
}

func itoa(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	panic("test helper only supports one digit")
}
