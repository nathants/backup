package pack

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"backup/internal/format"

	"github.com/klauspost/compress/zstd"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

const (
	maximumTarMemberSize = uint64(^uint64(0) >> 1)
	canonicalZstdWindow  = 8 << 20
)

var sodiumOnce sync.Once

type Created struct {
	Hash      string
	Size      uint64
	Objects   []format.ObjectEntry
	PartCount uint32
	partsPath string
	partsHash string
}

type StagedFile struct {
	Hash string
	Size uint64
	Path string
	Open *os.File
}

func encryptRecipients(recipients libsodium.KeyChains, input io.Reader, output io.Writer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recipient encryption failed: %v", recovered)
		}
	}()
	sodiumOnce.Do(libsodium.Init)
	keys, err := recipients.Latest()
	if err != nil {
		return err
	}
	return libsodium.StreamEncryptRecipients(keys, input, output)
}

func canonicalHeader(name string, size int64) *tar.Header {
	return &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     0o600,
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		ModTime:  time.Unix(0, 0).UTC(),
		Format:   tar.FormatPAX,
	}
}

func randomID() (string, error) {
	var data [16]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func ReadArchive(input io.Reader, expected map[string]uint64, consume func(hash string, size uint64, reader io.Reader) error) error {
	if len(expected) == 0 {
		return fmt.Errorf("expected member set is empty")
	}
	if consume == nil {
		return fmt.Errorf("member consumer is required")
	}
	remaining := make(map[string]uint64, len(expected))
	maximumBytes := uint64(1 << 20)
	for hash, size := range expected {
		if len(hash) != 128 || stringsToLower(hash) != hash {
			return fmt.Errorf("invalid expected member hash %q", hash)
		}
		if size > ^uint64(0)-4096 || ^uint64(0)-maximumBytes < size+4096 {
			return fmt.Errorf("expected archive size overflows")
		}
		maximumBytes += size + 4096
		remaining[hash] = size
	}
	if maximumBytes > uint64(^uint64(0)>>1)-1 {
		return fmt.Errorf("expected archive is too large")
	}
	originalDigest, _ := blake2b.New512(nil)
	originalCount := &countWriter{writer: originalDigest}
	limitedInput := &io.LimitedReader{R: input, N: int64(maximumBytes) + 1}
	reader := tar.NewReader(io.TeeReader(limitedInput, originalCount))
	canonicalDigest, _ := blake2b.New512(nil)
	canonicalCount := &countWriter{writer: canonicalDigest}
	canonicalWriter := tar.NewWriter(canonicalCount)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}
		if err := validateTarHeader(header); err != nil {
			return err
		}
		expectedSize, ok := remaining[header.Name]
		if !ok {
			return fmt.Errorf("tar contains unexpected member %s", header.Name)
		}
		if expectedSize != uint64(header.Size) {
			return fmt.Errorf("tar member %s size disagrees with metadata", header.Name)
		}
		if err := canonicalWriter.WriteHeader(canonicalHeader(header.Name, header.Size)); err != nil {
			return err
		}
		plainDigest, _ := blake2b.New512(nil)
		limited := &io.LimitedReader{R: io.TeeReader(reader, io.MultiWriter(canonicalWriter, plainDigest)), N: header.Size}
		if err := consume(header.Name, uint64(header.Size), limited); err != nil {
			return err
		}
		if limited.N != 0 {
			return fmt.Errorf("consumer did not read all bytes for tar member %s", header.Name)
		}
		if hex.EncodeToString(plainDigest.Sum(nil)) != header.Name {
			return fmt.Errorf("tar member %s plaintext hash mismatch", header.Name)
		}
		delete(remaining, header.Name)
	}
	if len(remaining) != 0 {
		missing := make([]string, 0, len(remaining))
		for hash := range remaining {
			missing = append(missing, hash)
		}
		sort.Strings(missing)
		return fmt.Errorf("tar is missing %d expected members, first %s", len(missing), missing[0])
	}
	if err := canonicalWriter.Close(); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, io.TeeReader(limitedInput, originalCount)); err != nil {
		return err
	}
	if limitedInput.N == 0 || originalCount.count > maximumBytes {
		return fmt.Errorf("tar exceeds its bounded canonical size")
	}
	if originalCount.count != canonicalCount.count || !bytes.Equal(originalDigest.Sum(nil), canonicalDigest.Sum(nil)) {
		return fmt.Errorf("tar has noncanonical headers, end markers, or trailing data")
	}
	return nil
}

func validateTarHeader(header *tar.Header) error {
	if header.Format != tar.FormatPAX || header.Typeflag != tar.TypeReg || len(header.Name) != 128 || stringsToLower(header.Name) != header.Name {
		return fmt.Errorf("tar member has invalid format, type, or name")
	}
	if _, err := hex.DecodeString(header.Name); err != nil {
		return fmt.Errorf("tar member has invalid hash name")
	}
	if header.Size < 0 || header.Mode != 0o600 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 {
		return fmt.Errorf("tar member %s has noncanonical metadata", header.Name)
	}
	if !header.ModTime.Equal(time.Unix(0, 0)) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
		return fmt.Errorf("tar member %s has noncanonical timestamps", header.Name)
	}
	expectedPAX := map[string]string{"path": header.Name}
	if header.Size > 8_589_934_591 {
		expectedPAX["size"] = strconv.FormatInt(header.Size, 10)
	}
	if len(header.PAXRecords) != len(expectedPAX) {
		return fmt.Errorf("tar member %s has unexpected PAX records", header.Name)
	}
	for key, value := range expectedPAX {
		if header.PAXRecords[key] != value {
			return fmt.Errorf("tar member %s has invalid PAX %s record", header.Name, key)
		}
	}
	return nil
}

func DecryptAndRead(ciphertext io.Reader, expectedHash string, expectedSize uint64, secretKey *libsodium.Keyring, expectedMembers map[string]uint64, consume func(string, uint64, io.Reader) error) error {
	if len(expectedHash) != 128 || stringsToLower(expectedHash) != expectedHash {
		return fmt.Errorf("invalid expected ciphertext hash")
	}
	if expectedSize > uint64(^uint64(0)>>1) {
		return fmt.Errorf("ciphertext is too large")
	}
	expectedDigest, err := hex.DecodeString(expectedHash)
	if err != nil {
		return err
	}
	hash, _ := blake2b.New512(nil)
	limitedCiphertext := &io.LimitedReader{R: ciphertext, N: int64(expectedSize) + 1}
	verifiedCiphertext := io.TeeReader(limitedCiphertext, hash)
	plainReader, plainWriter := io.Pipe()
	decryptResult := make(chan error, 1)
	go func() {
		err := decryptRecipients(secretKey, verifiedCiphertext, plainWriter)
		_ = plainWriter.CloseWithError(err)
		decryptResult <- err
	}()
	decompressor, err := zstd.NewReader(plainReader,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxMemory(canonicalZstdWindow),
		zstd.WithDecoderMaxWindow(canonicalZstdWindow),
	)
	if err != nil {
		_ = plainReader.CloseWithError(err)
		<-decryptResult
		return err
	}
	archiveErr := ReadArchive(decompressor, expectedMembers, consume)
	decompressor.Close()
	if archiveErr != nil {
		_ = plainReader.CloseWithError(archiveErr)
	}
	decryptErr := <-decryptResult
	if archiveErr != nil {
		return archiveErr
	}
	if decryptErr != nil {
		return decryptErr
	}
	if limitedCiphertext.N != 1 {
		return fmt.Errorf("ciphertext size disagrees with metadata or contains trailing bytes")
	}
	if !bytes.Equal(hash.Sum(nil), expectedDigest) {
		return fmt.Errorf("ciphertext BLAKE2b disagrees with metadata")
	}
	return nil
}

func decryptRecipients(secretKey *libsodium.Keyring, input io.Reader, output io.Writer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recipient decryption failed: %v", recovered)
		}
	}()
	sodiumOnce.Do(libsodium.Init)
	return secretKey.Decrypt(input, output)
}

type countWriter struct {
	writer io.Writer
	count  uint64
}

func (writer *countWriter) Write(data []byte) (int, error) {
	count, err := writer.writer.Write(data)
	writer.count += uint64(count)
	return count, err
}

func stringsToLower(value string) string {
	data := []byte(value)
	for index, char := range data {
		if char >= 'A' && char <= 'Z' {
			data[index] = char + ('a' - 'A')
		}
	}
	return string(data)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
