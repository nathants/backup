package backup

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

type CountWriter struct {
	Writer io.Writer
	Count  int64
}

func (writer *CountWriter) Write(data []byte) (int, error) {
	count, err := writer.Writer.Write(data)
	writer.Count += int64(count)
	return count, err
}

func CreatePack(root string, packName string, files []FileHash, publicKeys [][]byte, createdUTC string) (StagedPack, error) {
	InitCrypto()
	if len(files) == 0 {
		return StagedPack{}, fmt.Errorf("no files for pack")
	}
	staging := stagingDir(root)
	if err := os.MkdirAll(staging, 0755); err != nil {
		return StagedPack{}, err
	}
	packPath := filepath.Join(staging, packName)
	output, err := os.Create(packPath)
	if err != nil {
		return StagedPack{}, err
	}
	defer func() { _ = output.Close() }()
	hash, err := blake2b.New512(nil)
	if err != nil {
		return StagedPack{}, err
	}
	multiWriter := io.MultiWriter(output, hash)
	countingWriter := &CountWriter{Writer: multiWriter}

	pipeReader, pipeWriter := io.Pipe()
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if value := recover(); value != nil {
				errChan <- fmt.Errorf("encryption panic: %v", value)
			}
		}()
		err := libsodium.StreamEncryptRecipients(publicKeys, pipeReader, countingWriter)
		errChan <- err
	}()

	zstdWriter, err := zstd.NewWriter(pipeWriter)
	if err != nil {
		return StagedPack{}, err
	}
	tarWriter := tar.NewWriter(zstdWriter)
	for _, file := range files {
		input, err := os.Open(file.Path)
		if err != nil {
			return StagedPack{}, err
		}
		header := &tar.Header{
			Name:    file.Hash,
			Mode:    0644,
			Size:    file.Size,
			ModTime: time.Unix(0, 0),
		}
		err = tarWriter.WriteHeader(header)
		if err != nil {
			_ = input.Close()
			return StagedPack{}, err
		}
		_, err = io.Copy(tarWriter, input)
		_ = input.Close()
		if err != nil {
			return StagedPack{}, err
		}
	}
	err = tarWriter.Close()
	if err != nil {
		return StagedPack{}, err
	}
	err = zstdWriter.Close()
	if err != nil {
		return StagedPack{}, err
	}
	err = pipeWriter.Close()
	if err != nil {
		return StagedPack{}, err
	}
	err = <-errChan
	if err != nil {
		return StagedPack{}, err
	}

	pack := StagedPack{
		PackKey:    packName,
		CipherHash: fmt.Sprintf("%x", hash.Sum(nil)),
		CipherSize: countingWriter.Count,
		CreatedUTC: createdUTC,
		Path:       packPath,
	}
	for _, file := range files {
		pack.Hashes = append(pack.Hashes, file.Hash)
	}
	return pack, nil
}
