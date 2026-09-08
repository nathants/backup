package pack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"github.com/klauspost/compress/zstd"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

func TestCanonicalTarGoldenAndRead(t *testing.T) {
	data := []byte("alpha")
	plainDigest := blake2b.Sum512(data)
	name := hex.EncodeToString(plainDigest[:])
	archive, err := buildTestTar(name, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	const expectedDigest = "6264bddfd1529b860bc919e8fca60cafebdb57128289f0e17a6ce66b66e1bedd"
	if hex.EncodeToString(digest[:]) != expectedDigest {
		t.Fatalf("canonical tar digest changed: got %x", digest)
	}
	expected := map[string]uint64{name: uint64(len(data))}
	seen := 0
	if err := ReadArchive(bytes.NewReader(archive), expected, func(hash string, size uint64, reader io.Reader) error {
		data, err := io.ReadAll(reader)
		if err == nil && string(data) != "alpha" {
			t.Fatalf("data=%q", data)
		}
		seen++
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("seen=%d", seen)
	}
}

func TestLargeSizeUsesOnlyPathAndSizePAXRecords(t *testing.T) {
	var encoded bytes.Buffer
	writer := tar.NewWriter(&encoded)
	if err := writer.WriteHeader(canonicalHeader(strings.Repeat("a", 128), 1<<40)); err != nil {
		t.Fatal(err)
	}
	headerBytes := encoded.Bytes()
	digest := sha256.Sum256(headerBytes)
	const expectedDigest = "49e7e6d33716cae523d874242424500f33801c5aa9848af5cac9667f67ecc716"
	if hex.EncodeToString(digest[:]) != expectedDigest {
		t.Fatalf("large header digest changed: got %x", digest)
	}
	reader := tar.NewReader(bytes.NewReader(headerBytes))
	header, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if len(header.PAXRecords) != 2 || header.PAXRecords["path"] != header.Name || header.PAXRecords["size"] != "1099511627776" {
		t.Fatalf("unexpected PAX records: %#v", header.PAXRecords)
	}
}

func TestStreamingPackUploadsBoundedPartsAndAcceptsNonHashOrder(t *testing.T) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plainDirectory := t.TempDir()
	firstData := bytes.Repeat([]byte("z"), 400)
	secondData := bytes.Repeat([]byte("a"), 400)
	firstDigest := blake2b.Sum512(firstData)
	secondDigest := blake2b.Sum512(secondData)
	first := filepath.Join(plainDirectory, "first")
	second := filepath.Join(plainDirectory, "second")
	if err := os.WriteFile(first, firstData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, secondData, 0o600); err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	stage := filepath.Join(t.TempDir(), "parts")
	builder, err := NewStreamBuilder([][]byte{publicKey}, stage, 128, func(part *StreamPart) error {
		data, err := os.ReadFile(part.Path)
		if err != nil {
			return err
		}
		if uint64(len(data)) > 128 {
			t.Fatalf("part exceeded ceiling: %d", len(data))
		}
		ciphertext.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately use a non-hash-sorted order. Member order is capture order,
	// not a canonical hash-order invariant.
	for _, file := range []StagedFile{
		{Hash: hex.EncodeToString(firstDigest[:]), Size: uint64(len(firstData)), Path: first},
		{Hash: hex.EncodeToString(secondDigest[:]), Size: uint64(len(secondData)), Path: second},
	} {
		if err := builder.Add(file); err != nil {
			t.Fatal(err)
		}
	}
	created, err := builder.Close()
	if err != nil {
		t.Fatal(err)
	}
	if created.PartCount < 2 {
		t.Fatalf("parts=%d", created.PartCount)
	}
	var walked uint32
	if err := created.WalkParts(func(entry format.PackEntry) error {
		if entry.PartNumber != walked || entry.PartCount != created.PartCount || entry.PartSize > 128 {
			t.Fatalf("part metadata mismatch: %#v", entry)
		}
		walked++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if walked != created.PartCount {
		t.Fatalf("walked parts=%d, want %d", walked, created.PartCount)
	}
	catalog, err := os.OpenFile(created.partsPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	var changed [1]byte
	if _, err := catalog.ReadAt(changed[:], 4); err != nil {
		_ = catalog.Close()
		t.Fatal(err)
	}
	changed[0] ^= 1
	if _, err := catalog.WriteAt(changed[:], 4); err != nil {
		_ = catalog.Close()
		t.Fatal(err)
	}
	if err := catalog.Sync(); err != nil {
		_ = catalog.Close()
		t.Fatal(err)
	}
	if err := catalog.Close(); err != nil {
		t.Fatal(err)
	}
	if err := created.WalkParts(func(format.PackEntry) error { return nil }); err == nil {
		t.Fatal("mutated file-backed part catalog was accepted")
	}
	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(stage)
	if err != nil || len(entries) != 0 {
		t.Fatalf("streaming part files were retained: %#v %v", entries, err)
	}
	expected := map[string]uint64{
		hex.EncodeToString(firstDigest[:]):  uint64(len(firstData)),
		hex.EncodeToString(secondDigest[:]): uint64(len(secondData)),
	}
	if err := DecryptAndRead(bytes.NewReader(ciphertext.Bytes()), created.Hash, created.Size, secretKey, expected, discardMember); err != nil {
		t.Fatal(err)
	}
}

func TestStreamingPackIdentityFailurePoisonsBuilder(t *testing.T) {
	libsodium.Init()
	publicKey, _, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("same-sized payload")
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := blake2b.Sum512([]byte("wrong-sized-data!"))
	valid := blake2b.Sum512(data)
	builder, err := NewStreamBuilder([][]byte{publicKey}, t.TempDir(), 1<<20, func(*StreamPart) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Add(StagedFile{Hash: hex.EncodeToString(wrong[:]), Size: uint64(len(data)), Path: path}); err == nil {
		t.Fatal("same-size wrong-hash member was accepted")
	}
	if err := builder.Add(StagedFile{Hash: hex.EncodeToString(valid[:]), Size: uint64(len(data)), Path: path}); err == nil {
		t.Fatal("builder accepted another member after emitting a failed member header")
	}
	if _, err := builder.Close(); err == nil {
		t.Fatal("builder closed successfully after a post-header identity failure")
	}
}

func TestReadArchiveRejectsNoncanonicalAndTrailingData(t *testing.T) {
	digest := blake2b.Sum512([]byte("x"))
	name := hex.EncodeToString(digest[:])
	canonical, err := buildTestTar(name, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]uint64{name: 1}
	if err := ReadArchive(bytes.NewReader(canonical), expected, discardMember); err != nil {
		t.Fatalf("canonical baseline rejected: %v", err)
	}
	for title, data := range map[string][]byte{
		"trailing":      append(append([]byte(nil), canonical...), 0),
		"truncated end": canonical[:len(canonical)-1024],
	} {
		t.Run(title, func(t *testing.T) {
			if err := ReadArchive(bytes.NewReader(data), expected, discardMember); err == nil || err.Error() != "tar has noncanonical headers, end markers, or trailing data" {
				t.Fatalf("expected canonical framing rejection, got %v", err)
			}
		})
	}
	withExtraPAX, err := buildTestTar(name, []byte("x"), map[string]string{"comment": "forbidden"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReadArchive(bytes.NewReader(withExtraPAX), expected, discardMember); err == nil || err.Error() != "tar member "+name+" has unexpected PAX records" {
		t.Fatalf("expected PAX-record rejection, got %v", err)
	}
}

func TestDecryptRejectsOversizedZstdWindow(t *testing.T) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 9<<20)
	plainDigest := blake2b.Sum512(data)
	name := hex.EncodeToString(plainDigest[:])
	archive, err := buildTestTar(name, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(64<<20))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := encryptRecipients([][]byte{publicKey}, bytes.NewReader(compressed.Bytes()), &ciphertext); err != nil {
		t.Fatal(err)
	}
	cipherDigest := blake2b.Sum512(ciphertext.Bytes())
	err = DecryptAndRead(
		bytes.NewReader(ciphertext.Bytes()), hex.EncodeToString(cipherDigest[:]), uint64(ciphertext.Len()), secretKey,
		map[string]uint64{name: uint64(len(data))}, discardMember,
	)
	if err == nil {
		t.Fatal("pack with a zstd window larger than the canonical encoder limit was accepted")
	}
}

func TestDecryptRejectsWrongRecipientAndTrailingCiphertext(t *testing.T) {
	libsodium.Init()
	publicKey, secretKey, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongSecret, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	plainDigest := blake2b.Sum512([]byte("x"))
	name := hex.EncodeToString(plainDigest[:])
	archive, err := buildTestTar(name, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var compressedEncrypted bytes.Buffer
	if err := encryptTestArchive(bytes.NewReader(archive), [][]byte{publicKey}, &compressedEncrypted); err != nil {
		t.Fatal(err)
	}
	cipher := compressedEncrypted.Bytes()
	digest := blake2b.Sum512(cipher)
	hash := hex.EncodeToString(digest[:])
	expected := map[string]uint64{name: 1}
	if err := DecryptAndRead(bytes.NewReader(cipher), hash, uint64(len(cipher)), secretKey, expected, discardMember); err != nil {
		t.Fatalf("valid encrypted baseline rejected: %v", err)
	}
	if err := DecryptAndRead(bytes.NewReader(cipher), hash, uint64(len(cipher)), wrongSecret, expected, discardMember); err == nil || err.Error() != "read tar header: no recipient matched secret key" {
		t.Fatalf("expected recipient rejection, got %v", err)
	}
	trailing := append(append([]byte(nil), cipher...), 0)
	trailingDigest := blake2b.Sum512(trailing)
	if err := DecryptAndRead(bytes.NewReader(trailing), hex.EncodeToString(trailingDigest[:]), uint64(len(trailing)), secretKey, expected, discardMember); err == nil || err.Error() != "ciphertext size disagrees with metadata or contains trailing bytes" {
		t.Fatalf("expected trailing-ciphertext rejection, got %v", err)
	}
}

func encryptTestArchive(input io.Reader, recipients [][]byte, output io.Writer) error {
	plainReader, plainWriter := io.Pipe()
	result := make(chan error, 1)
	go func() {
		err := encryptRecipients(recipients, plainReader, output)
		_ = plainReader.CloseWithError(err)
		result <- err
	}()
	compressor, err := zstd.NewWriter(plainWriter, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(canonicalZstdWindow))
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(compressor, input)
	if closeErr := compressor.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if closeErr := plainWriter.CloseWithError(copyErr); copyErr == nil {
		copyErr = closeErr
	}
	encryptErr := <-result
	if copyErr != nil {
		return copyErr
	}
	return encryptErr
}

func buildTestTar(name string, data []byte, pax map[string]string) ([]byte, error) {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	header := canonicalHeader(name, int64(len(data)))
	header.PAXRecords = pax
	if err := writer.WriteHeader(header); err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func discardMember(_ string, _ uint64, reader io.Reader) error {
	_, err := io.Copy(io.Discard, reader)
	return err
}
