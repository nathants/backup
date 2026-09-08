package pack

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
)

const fuzzPackPayload = "seed payload"

// A fixed public test key keeps saved ciphertext corpus entries decryptable
// across workers and later runs. It is never used for real backup content.
func fuzzPackKey(tb testing.TB) *ecdh.PrivateKey {
	tb.Helper()
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func fuzzPackArchive(tb testing.TB) []byte {
	tb.Helper()
	digest := blake2b.Sum512([]byte(fuzzPackPayload))
	archive, err := buildTestTar(hex.EncodeToString(digest[:]), []byte(fuzzPackPayload), nil)
	if err != nil {
		tb.Fatal(err)
	}
	return archive
}

func readFuzzPack(tb testing.TB, data, secret []byte) error {
	tb.Helper()
	digest := blake2b.Sum512(data)
	memberDigest := blake2b.Sum512([]byte(fuzzPackPayload))
	memberHash := hex.EncodeToString(memberDigest[:])
	var plaintext bytes.Buffer
	seen := 0
	err := DecryptAndRead(bytes.NewReader(data), hex.EncodeToString(digest[:]), uint64(len(data)), secret,
		map[string]uint64{memberHash: uint64(len(fuzzPackPayload))},
		func(hash string, size uint64, reader io.Reader) error {
			if hash != memberHash || size != uint64(len(fuzzPackPayload)) {
				tb.Fatal("unexpected member reached consumer")
			}
			seen++
			_, err := io.Copy(&plaintext, reader)
			return err
		})
	if err == nil && (seen != 1 || plaintext.String() != fuzzPackPayload) {
		tb.Fatal("successful encrypted read did not deliver the expected member")
	}
	return err
}

func FuzzEncryptedPackReader(f *testing.F) {
	key := fuzzPackKey(f)
	var valid bytes.Buffer
	if err := encryptTestArchive(bytes.NewReader(fuzzPackArchive(f)), [][]byte{key.PublicKey().Bytes()}, &valid); err != nil {
		f.Fatal(err)
	}
	if err := readFuzzPack(f, valid.Bytes(), key.Bytes()); err != nil {
		f.Fatalf("valid encrypted seed rejected: %v", err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add([]byte("not encrypted pack data"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = readFuzzPack(t, data, key.Bytes())
	})
}

func FuzzAuthenticatedPackReader(f *testing.F) {
	key := fuzzPackKey(f)
	archive := fuzzPackArchive(f)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(canonicalZstdWindow))
	if err != nil {
		f.Fatal(err)
	}
	compressed := encoder.EncodeAll(archive, nil)
	if err := encoder.Close(); err != nil {
		f.Fatal(err)
	}
	// Mutate either tar bytes before compression, or compressed bytes before
	// encryption. Fresh real authentication lets every mutation reach the
	// tar/zstd readers instead of dying at the cryptographic barrier.
	wrap := func(tb testing.TB, data []byte, isCompressed bool) []byte {
		tb.Helper()
		var encrypted bytes.Buffer
		var err error
		if isCompressed {
			err = encryptRecipients([][]byte{key.PublicKey().Bytes()}, bytes.NewReader(data), &encrypted)
		} else {
			err = encryptTestArchive(bytes.NewReader(data), [][]byte{key.PublicKey().Bytes()}, &encrypted)
		}
		if err != nil {
			tb.Fatal(err)
		}
		return encrypted.Bytes()
	}
	for _, seed := range []struct {
		data       []byte
		compressed bool
	}{{archive, false}, {compressed, true}} {
		if err := readFuzzPack(f, wrap(f, seed.data, seed.compressed), key.Bytes()); err != nil {
			f.Fatalf("valid authenticated seed rejected: %v", err)
		}
		f.Add(seed.data, seed.compressed)
	}
	f.Add([]byte("not a tar archive"), false)
	f.Add([]byte("not zstd"), true)
	f.Fuzz(func(t *testing.T, data []byte, isCompressed bool) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		err := readFuzzPack(t, wrap(t, data, isCompressed), key.Bytes())
		if err == nil && !isCompressed && !bytes.Equal(data, archive) {
			t.Fatal("noncanonical authenticated archive was accepted")
		}
	})
}

func FuzzCanonicalTarReader(f *testing.F) {
	validBytes := fuzzPackArchive(f)
	digest := blake2b.Sum512([]byte(fuzzPackPayload))
	hash := hex.EncodeToString(digest[:])
	f.Add(validBytes)
	f.Add([]byte("not a tar archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		err := ReadArchive(bytes.NewReader(data), map[string]uint64{hash: uint64(len(fuzzPackPayload))}, discardMember)
		if err == nil && !bytes.Equal(data, validBytes) {
			t.Fatal("noncanonical archive was accepted")
		}
	})
}
