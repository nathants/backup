package metadatachain

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"backup/internal/format"
	"backup/internal/repository"

	"github.com/nathants/go-libsodium"
	"golang.org/x/crypto/blake2b"
)

// Build streams Git bundle creation directly through recipient encryption into
// bounded parts. It never stages a plaintext bundle or a complete encrypted
// bundle. maxCiphertextBytes protects caller-reserved filesystem headroom.
func Build(repo *repository.Managed, repositoryUUID, base, tip string, sequence uint64, recipients libsodium.KeyChains, staging string, partSize, maxCiphertextBytes uint64) (Result, error) {
	if repo == nil || repositoryUUID == "" || tip == "" || len(recipients) == 0 || partSize == 0 || partSize > uint64(^uint64(0)>>1) || maxCiphertextBytes == 0 {
		return Result{}, fmt.Errorf("invalid metadata-chain build arguments")
	}
	if partSize > maxCiphertextBytes {
		partSize = maxCiphertextBytes
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return Result{}, err
	}
	if err := os.Chmod(staging, 0o700); err != nil {
		return Result{}, err
	}
	sink := &metadataPartSink{directory: staging, partSize: partSize, remainingBudget: maxCiphertextBytes}
	sink.whole, _ = blake2b.New512(nil)
	keep := false
	defer func() {
		if !keep {
			sink.Abort()
		}
	}()
	plainReader, plainWriter := io.Pipe()
	bundleDone := make(chan error, 1)
	go func() {
		err := repo.WriteBundle(base, tip, plainWriter)
		_ = plainWriter.CloseWithError(err)
		bundleDone <- err
	}()
	encryptionErr := encrypt(plainReader, recipients, sink)
	if encryptionErr != nil {
		_ = plainReader.CloseWithError(encryptionErr)
	} else {
		_ = plainReader.Close()
	}
	bundleErr := <-bundleDone
	if encryptionErr != nil {
		sink.Abort()
		return Result{}, encryptionErr
	}
	if bundleErr != nil {
		sink.Abort()
		return Result{}, bundleErr
	}
	if err := sink.Close(); err != nil {
		sink.Abort()
		return Result{}, err
	}
	if sink.total == 0 || len(sink.parts) == 0 {
		sink.Abort()
		return Result{}, fmt.Errorf("encrypted metadata bundle is empty")
	}
	partCount := uint32(len(sink.parts))
	manifestParts := make([]format.ManifestPart, partCount)
	result := Result{Parts: make([]StagedPart, partCount)}
	for index := range sink.parts {
		sink.parts[index].Manifest.Count = partCount
		manifestParts[index] = sink.parts[index].Manifest
		result.Parts[index] = sink.parts[index]
	}
	kind, manifestBase := format.BundleFull, "-"
	if base != "" {
		kind, manifestBase = format.BundleIncremental, base
	}
	manifest := format.MetadataManifest{
		RepositoryUUID: repositoryUUID, Sequence: sequence, BaseCommit: manifestBase, TipCommit: tip, Kind: kind,
		BundleHash: hex.EncodeToString(sink.whole.Sum(nil)), BundleSize: sink.total, Parts: manifestParts,
	}
	manifestData, err := manifest.MarshalText()
	if err != nil {
		return Result{}, err
	}
	manifestDigest := blake2b.Sum512(manifestData)
	manifestObjectID, err := randomID()
	if err != nil {
		return Result{}, err
	}
	manifestPath := filepath.Join(staging, "metadata.manifest")
	if err := atomicWrite(manifestPath, manifestData); err != nil {
		return Result{}, err
	}
	result.Manifest, result.ManifestHash, result.ManifestObjectID, result.ManifestPath = manifest, hex.EncodeToString(manifestDigest[:]), manifestObjectID, manifestPath
	if err := syncDirectory(staging); err != nil {
		return Result{}, err
	}
	keep = true
	return result, nil
}

type metadataPartSink struct {
	directory       string
	partSize        uint64
	remainingBudget uint64
	whole           hash.Hash
	total           uint64
	parts           []StagedPart
	file            *os.File
	path            string
	size            uint64
	blake           hash.Hash
	sha             hash.Hash
	md5             hash.Hash
	closed          bool
	failed          error
}

func (sink *metadataPartSink) Write(data []byte) (int, error) {
	if sink.failed != nil {
		return 0, sink.failed
	}
	if sink.closed {
		return 0, fmt.Errorf("metadata part sink is closed")
	}
	written := 0
	for len(data) != 0 {
		if sink.remainingBudget == 0 {
			sink.failed = fmt.Errorf("encrypted metadata bundle exceeds the safe %d-byte staging budget", sink.total)
			return written, sink.failed
		}
		if sink.file == nil {
			if err := sink.openPart(); err != nil {
				sink.failed = err
				return written, err
			}
		}
		remainingPart := sink.partSize - sink.size
		chunk := data
		if uint64(len(chunk)) > remainingPart {
			chunk = chunk[:remainingPart]
		}
		if uint64(len(chunk)) > sink.remainingBudget {
			chunk = chunk[:sink.remainingBudget]
		}
		count, err := sink.file.Write(chunk)
		if count > 0 {
			piece := chunk[:count]
			_, _ = sink.whole.Write(piece)
			_, _ = sink.blake.Write(piece)
			_, _ = sink.sha.Write(piece)
			_, _ = sink.md5.Write(piece)
			sink.size += uint64(count)
			sink.total += uint64(count)
			sink.remainingBudget -= uint64(count)
			written += count
			data = data[count:]
		}
		if err != nil {
			sink.failed = err
			return written, err
		}
		if count == 0 {
			sink.failed = io.ErrShortWrite
			return written, sink.failed
		}
		if sink.size == sink.partSize {
			if err := sink.finishPart(); err != nil {
				sink.failed = err
				return written, err
			}
		}
	}
	return written, nil
}

func (sink *metadataPartSink) openPart() error {
	if len(sink.parts) >= format.MaximumMetadataManifestParts {
		return fmt.Errorf("metadata bundle has too many parts for a bounded completion manifest")
	}
	objectID, err := randomID()
	if err != nil {
		return err
	}
	path := filepath.Join(sink.directory, fmt.Sprintf("metadata-part-%08d-%s", len(sink.parts), objectID))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	sink.file, sink.path, sink.size = file, path, 0
	sink.blake, _ = blake2b.New512(nil)
	sink.sha, sink.md5 = sha256.New(), md5.New()
	return nil
}

func (sink *metadataPartSink) finishPart() error {
	if sink.file == nil || sink.size == 0 {
		return nil
	}
	file, path, size := sink.file, sink.path, sink.size
	sink.file, sink.path, sink.size = nil, "", 0
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	name := filepath.Base(path)
	objectID := name[len(name)-32:]
	sink.parts = append(sink.parts, StagedPart{Path: path, Manifest: format.ManifestPart{
		Number: uint32(len(sink.parts)), ObjectID: objectID, Hash: hex.EncodeToString(sink.blake.Sum(nil)),
		SHA256: hex.EncodeToString(sink.sha.Sum(nil)), MD5: hex.EncodeToString(sink.md5.Sum(nil)), Size: size,
	}})
	return nil
}

func (sink *metadataPartSink) Close() error {
	if sink.closed {
		return sink.failed
	}
	sink.closed = true
	if sink.failed != nil {
		return sink.failed
	}
	return sink.finishPart()
}

func (sink *metadataPartSink) Abort() {
	if sink.file != nil {
		_ = sink.file.Close()
		_ = os.Remove(sink.path)
		sink.file = nil
	}
	for _, part := range sink.parts {
		_ = os.Remove(part.Path)
	}
	sink.parts = nil
}

var _ io.Writer = (*metadataPartSink)(nil)
