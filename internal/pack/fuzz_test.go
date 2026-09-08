package pack

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	libsodium "github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

func FuzzEncryptedPackReader(f *testing.F) {
	libsodium.Init()
	memberDigest := blake2b.Sum512(nil)
	memberHash := hex.EncodeToString(memberDigest[:])
	f.Add([]byte{})
	f.Add([]byte("not encrypted pack data"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ciphertextDigest := blake2b.Sum512(data)
		_ = DecryptAndRead(
			bytes.NewReader(data),
			hex.EncodeToString(ciphertextDigest[:]),
			uint64(len(data)),
			make([]byte, 32),
			map[string]uint64{memberHash: 0},
			func(_ string, _ uint64, reader io.Reader) error {
				_, err := io.Copy(io.Discard, reader)
				return err
			},
		)
	})
}

func FuzzCanonicalTarReader(f *testing.F) {
	payload := []byte("seed payload")
	digest := blake2b.Sum512(payload)
	hash := hex.EncodeToString(digest[:])
	var valid bytes.Buffer
	writer := tar.NewWriter(&valid)
	if err := writer.WriteHeader(canonicalHeader(hash, int64(len(payload)))); err != nil {
		f.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		f.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		f.Fatal(err)
	}
	validBytes := append([]byte(nil), valid.Bytes()...)
	f.Add(validBytes)
	f.Add([]byte("not a tar archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		err := ReadArchive(bytes.NewReader(data), map[string]uint64{hash: uint64(len(payload))}, func(_ string, _ uint64, reader io.Reader) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		})
		if err == nil && !bytes.Equal(data, validBytes) {
			t.Fatal("noncanonical archive was accepted")
		}
	})
}
