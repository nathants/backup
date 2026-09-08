package metadatachain

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"backup/internal/format"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

var sodiumOnce sync.Once

type StagedPart struct {
	Manifest format.ManifestPart
	Path     string
}

type Result struct {
	Manifest         format.MetadataManifest
	ManifestHash     string
	ManifestObjectID string
	ManifestPath     string
	Parts            []StagedPart
}

func encrypt(input io.Reader, recipients [][]byte, output io.Writer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("metadata encryption failed: %v", recovered)
		}
	}()
	sodiumOnce.Do(libsodium.Init)
	return libsodium.StreamEncryptRecipients(recipients, input, output)
}

func Decrypt(ciphertext io.Reader, expectedHash string, expectedSize uint64, secretKey []byte, output io.Writer) error {
	if expectedSize > uint64(^uint64(0)>>1)-1 || len(expectedHash) != 128 {
		return fmt.Errorf("invalid encrypted metadata identity")
	}
	expectedDigest, err := hex.DecodeString(expectedHash)
	if err != nil {
		return err
	}
	hash, _ := blake2b.New512(nil)
	limited := &io.LimitedReader{R: ciphertext, N: int64(expectedSize) + 1}
	counting := &countWriter{writer: hash}
	tee := io.TeeReader(limited, counting)
	if err := decrypt(secretKey, tee, output); err != nil {
		return err
	}
	if limited.N != 1 || counting.count != expectedSize || !bytes.Equal(hash.Sum(nil), expectedDigest) {
		return fmt.Errorf("encrypted metadata size or hash mismatch")
	}
	return nil
}

func decrypt(secretKey []byte, input io.Reader, output io.Writer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("metadata decryption failed: %v", recovered)
		}
	}()
	sodiumOnce.Do(libsodium.Init)
	return libsodium.StreamDecryptRecipients(secretKey, input, output)
}

func hashBytes(data []byte) objectIdentity {
	digest := blake2b.Sum512(data)
	return objectIdentity{Size: uint64(len(data)), BLAKE2b: hex.EncodeToString(digest[:])}
}

type objectIdentity struct {
	Size    uint64
	BLAKE2b string
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

func randomID() (string, error) {
	var data [16]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(data[:]), nil
}

func atomicWrite(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
