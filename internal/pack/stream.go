package pack

import (
	"archive/tar"
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"backup/internal/format"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const (
	MaximumMembersPerPack = 10_000
	streamPartRecordBytes = 4 + blake2b.Size + sha256.Size + md5.Size + 8 + 16
)

type StreamPart struct {
	Number   uint32
	Hash     string
	SHA256   string
	MD5      string
	Size     uint64
	ObjectID string
	Path     string
}

type PartConsumer func(*StreamPart) error

type StreamBuilder struct {
	archive      *tar.Writer
	compression  *zstd.Encoder
	plainWriter  *io.PipeWriter
	encryptDone  chan error
	sink         *partSink
	files        []StagedFile
	seen         map[string]bool
	closed       bool
	pipelineFail error
}

func NewStreamBuilder(recipients [][]byte, stagingDirectory string, partSize uint64, consume PartConsumer) (*StreamBuilder, error) {
	if len(recipients) == 0 || consume == nil {
		return nil, fmt.Errorf("streaming pack requires recipients and a part consumer")
	}
	if partSize == 0 || partSize > uint64(^uint64(0)>>1) {
		return nil, fmt.Errorf("invalid part size %d", partSize)
	}
	if err := os.MkdirAll(stagingDirectory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return nil, err
	}
	sink, err := newPartSink(stagingDirectory, partSize, consume)
	if err != nil {
		return nil, err
	}
	packHash, _ := blake2b.New512(nil)
	sink.packHash = packHash
	plainReader, plainWriter := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := encryptRecipients(recipients, plainReader, sink)
		if err == nil {
			err = sink.Close()
		} else {
			sink.Abort()
		}
		_ = plainReader.CloseWithError(err)
		done <- err
	}()
	compression, err := zstd.NewWriter(plainWriter, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(canonicalZstdWindow))
	if err != nil {
		_ = plainWriter.CloseWithError(err)
		<-done
		return nil, err
	}
	return &StreamBuilder{
		archive: tar.NewWriter(compression), compression: compression, plainWriter: plainWriter,
		encryptDone: done, sink: sink, seen: make(map[string]bool),
	}, nil
}

func (builder *StreamBuilder) Add(file StagedFile) error {
	if builder == nil || builder.closed {
		return fmt.Errorf("streaming pack is closed")
	}
	if builder.pipelineFail != nil {
		return builder.pipelineFail
	}
	if len(builder.files) >= MaximumMembersPerPack {
		return fmt.Errorf("logical pack exceeds %d members", MaximumMembersPerPack)
	}
	if len(file.Hash) != 128 || file.Size > maximumTarMemberSize || (file.Path == "" && file.Open == nil) || builder.seen[file.Hash] {
		return fmt.Errorf("invalid or duplicate staged pack member")
	}
	if _, err := hex.DecodeString(file.Hash); err != nil {
		return fmt.Errorf("invalid staged pack member hash")
	}
	input := file.Open
	closeInput := false
	if input == nil {
		fd, err := unix.Open(file.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("open captured plaintext: %w", err)
		}
		input = os.NewFile(uintptr(fd), file.Path)
		closeInput = true
	}
	if closeInput {
		defer input.Close()
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind captured plaintext: %w", err)
	}
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != file.Size {
		return fmt.Errorf("captured plaintext changed before packing")
	}
	if err := builder.archive.WriteHeader(canonicalHeader(file.Hash, int64(file.Size))); err != nil {
		builder.pipelineFail = err
		return err
	}
	digest, _ := blake2b.New512(nil)
	count, err := io.CopyBuffer(io.MultiWriter(builder.archive, digest), input, make([]byte, 1<<20))
	if err != nil {
		builder.pipelineFail = err
		return err
	}
	if uint64(count) != file.Size || hex.EncodeToString(digest.Sum(nil)) != file.Hash {
		builder.pipelineFail = fmt.Errorf("captured plaintext identity changed before packing")
		return builder.pipelineFail
	}
	builder.seen[file.Hash] = true
	builder.files = append(builder.files, StagedFile{Hash: file.Hash, Size: file.Size})
	return nil
}

func (builder *StreamBuilder) Close() (Created, error) {
	if builder == nil || builder.closed {
		return Created{}, fmt.Errorf("streaming pack is already closed")
	}
	builder.closed = true
	writeErr := builder.pipelineFail
	if closeErr := builder.archive.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if closeErr := builder.compression.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if closeErr := builder.plainWriter.CloseWithError(writeErr); writeErr == nil {
		writeErr = closeErr
	}
	encryptionErr := <-builder.encryptDone
	if writeErr != nil {
		builder.sink.Abort()
		return Created{}, writeErr
	}
	if encryptionErr != nil {
		builder.sink.Abort()
		return Created{}, encryptionErr
	}
	if len(builder.files) == 0 || builder.sink.partCount == 0 {
		builder.sink.Abort()
		return Created{}, fmt.Errorf("streaming pack is empty")
	}
	packHash := hex.EncodeToString(builder.sink.packHash.Sum(nil))
	created := Created{
		Hash: packHash, Size: builder.sink.packSize,
		PartCount: builder.sink.partCount, partsPath: builder.sink.metadataPath,
		partsHash: hex.EncodeToString(builder.sink.metadataHash.Sum(nil)),
	}
	for _, file := range builder.files {
		created.Objects = append(created.Objects, format.ObjectEntry{PlaintextHash: file.Hash, PlaintextSize: file.Size, PackHash: packHash})
	}
	return created, nil
}

func (builder *StreamBuilder) Abort() {
	if builder == nil || builder.closed {
		return
	}
	builder.closed = true
	err := fmt.Errorf("streaming pack aborted")
	_ = builder.archive.Close()
	_ = builder.compression.Close()
	_ = builder.plainWriter.CloseWithError(err)
	<-builder.encryptDone
	builder.sink.Abort()
}

func writeStreamPartRecord(output io.Writer, part StreamPart) error {
	if output == nil || part.Size == 0 {
		return fmt.Errorf("invalid streamed pack part")
	}
	var record [streamPartRecordBytes]byte
	binary.BigEndian.PutUint32(record[0:4], part.Number)
	fields := []struct {
		text  string
		bytes []byte
		label string
	}{
		{part.Hash, record[4:68], "BLAKE2b"},
		{part.SHA256, record[68:100], "SHA-256"},
		{part.MD5, record[100:116], "MD5"},
		{part.ObjectID, record[124:140], "object ID"},
	}
	for _, field := range fields {
		decoded, err := hex.DecodeString(field.text)
		if err != nil || len(decoded) != len(field.bytes) {
			return fmt.Errorf("invalid streamed pack part %s", field.label)
		}
		copy(field.bytes, decoded)
	}
	binary.BigEndian.PutUint64(record[116:124], part.Size)
	written, err := output.Write(record[:])
	if err == nil && written != len(record) {
		err = io.ErrShortWrite
	}
	return err
}

// WalkParts reads the file-backed physical catalog for a completed pack. The
// stream builder retains a fixed amount of memory regardless of part count.
func (created Created) WalkParts(visit func(format.PackEntry) error) (returnErr error) {
	if created.PartCount == 0 || created.partsPath == "" || len(created.partsHash) != 128 || visit == nil {
		return fmt.Errorf("completed pack has no readable part catalog")
	}
	if _, err := hex.DecodeString(created.partsHash); err != nil {
		return fmt.Errorf("completed pack has an invalid part-catalog identity")
	}
	fd, err := unix.Open(created.partsPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), created.partsPath)
	defer func() {
		if closeErr := file.Close(); returnErr == nil {
			returnErr = closeErr
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	expectedBytes := uint64(created.PartCount) * streamPartRecordBytes
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Size < 0 || uint64(stat.Size) != expectedBytes {
		return fmt.Errorf("completed pack part catalog changed")
	}
	metadataHash, _ := blake2b.New512(nil)
	reader := bufio.NewReaderSize(io.TeeReader(file, metadataHash), 256<<10)
	var total uint64
	for number := uint32(0); number < created.PartCount; number++ {
		var record [streamPartRecordBytes]byte
		if _, err := io.ReadFull(reader, record[:]); err != nil {
			return fmt.Errorf("read completed pack part %d: %w", number, err)
		}
		if binary.BigEndian.Uint32(record[0:4]) != number {
			return fmt.Errorf("completed pack parts are not contiguous")
		}
		entry := format.PackEntry{
			PackHash: created.Hash, PartNumber: number, PartCount: created.PartCount,
			PartHash: hex.EncodeToString(record[4:68]), PartSHA256: hex.EncodeToString(record[68:100]),
			PartMD5: hex.EncodeToString(record[100:116]), PartSize: binary.BigEndian.Uint64(record[116:124]),
			ObjectID: hex.EncodeToString(record[124:140]),
		}
		if _, err := format.MarshalPackEntry(entry); err != nil {
			return fmt.Errorf("invalid completed pack part %d: %w", number, err)
		}
		if ^uint64(0)-total < entry.PartSize {
			return fmt.Errorf("completed pack part sizes overflow")
		}
		total += entry.PartSize
		if err := visit(entry); err != nil {
			return err
		}
	}
	if total != created.Size || hex.EncodeToString(metadataHash.Sum(nil)) != created.partsHash {
		return fmt.Errorf("completed pack part catalog identity changed")
	}
	return nil
}

// Remove releases the completed pack's private part-catalog staging file.
func (created *Created) Remove() error {
	if created == nil || created.partsPath == "" {
		return nil
	}
	path := created.partsPath
	created.partsPath = ""
	created.partsHash = ""
	return os.Remove(path)
}

type partSink struct {
	directory     string
	partSize      uint64
	consume       PartConsumer
	packHash      hash.Hash
	packSize      uint64
	partCount     uint32
	metadataFile  *os.File
	metadataPath  string
	metadataHash  hash.Hash
	metadataWrite *bufio.Writer
	file          *os.File
	path          string
	size          uint64
	blake         hash.Hash
	sha           hash.Hash
	md5           hash.Hash
	failed        error
	closed        bool
}

func newPartSink(directory string, partSize uint64, consume PartConsumer) (*partSink, error) {
	file, err := os.CreateTemp(directory, ".pack-parts-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	metadataHash, _ := blake2b.New512(nil)
	return &partSink{
		directory: directory, partSize: partSize, consume: consume,
		metadataFile: file, metadataPath: path, metadataHash: metadataHash,
		metadataWrite: bufio.NewWriterSize(io.MultiWriter(file, metadataHash), 256<<10),
	}, nil
}

func (sink *partSink) Write(data []byte) (int, error) {
	if sink.failed != nil {
		return 0, sink.failed
	}
	if sink.closed {
		return 0, fmt.Errorf("ciphertext part sink is closed")
	}
	written := 0
	for len(data) != 0 {
		if sink.file == nil {
			if err := sink.openPart(); err != nil {
				sink.failed = err
				return written, err
			}
		}
		remaining := sink.partSize - sink.size
		chunk := data
		if uint64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		if ^uint64(0)-sink.packSize < uint64(len(chunk)) {
			sink.failed = fmt.Errorf("encrypted pack size overflow")
			return written, sink.failed
		}
		count, err := sink.file.Write(chunk)
		if count > 0 {
			piece := chunk[:count]
			_, _ = sink.packHash.Write(piece)
			_, _ = sink.blake.Write(piece)
			_, _ = sink.sha.Write(piece)
			_, _ = sink.md5.Write(piece)
			sink.size += uint64(count)
			sink.packSize += uint64(count)
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

func (sink *partSink) openPart() error {
	if sink.partCount == ^uint32(0) {
		return fmt.Errorf("pack has too many ciphertext parts")
	}
	file, err := os.CreateTemp(sink.directory, ".cipher-part-*")
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}
	sink.file, sink.path, sink.size = file, file.Name(), 0
	sink.blake, _ = blake2b.New512(nil)
	sink.sha, sink.md5 = sha256.New(), md5.New()
	return nil
}

func (sink *partSink) finishPart() error {
	if sink.file == nil || sink.size == 0 {
		return nil
	}
	path := sink.path
	file := sink.file
	sink.file, sink.path = nil, ""
	defer os.Remove(path)
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	objectID, err := randomID()
	if err != nil {
		return err
	}
	part := StreamPart{
		Number: sink.partCount, Hash: hex.EncodeToString(sink.blake.Sum(nil)),
		SHA256: hex.EncodeToString(sink.sha.Sum(nil)), MD5: hex.EncodeToString(sink.md5.Sum(nil)),
		Size: sink.size, ObjectID: objectID, Path: path,
	}
	if err := sink.consume(&part); err != nil {
		return err
	}
	if part.ObjectID == "" {
		return fmt.Errorf("part consumer removed object identity")
	}
	if err := writeStreamPartRecord(sink.metadataWrite, part); err != nil {
		return err
	}
	sink.partCount++
	sink.size = 0
	return nil
}

func (sink *partSink) Close() error {
	if sink.closed {
		return sink.failed
	}
	sink.closed = true
	if sink.failed != nil {
		sink.Abort()
		return sink.failed
	}
	if err := sink.finishPart(); err != nil {
		sink.failed = err
		sink.Abort()
		return err
	}
	if err := sink.metadataWrite.Flush(); err != nil {
		sink.failed = err
		sink.Abort()
		return err
	}
	if err := sink.metadataFile.Sync(); err != nil {
		sink.failed = err
		sink.Abort()
		return err
	}
	if err := sink.metadataFile.Close(); err != nil {
		sink.failed = err
		sink.Abort()
		return err
	}
	sink.metadataFile = nil
	sink.metadataWrite = nil
	return syncDirectory(sink.directory)
}

func (sink *partSink) Abort() {
	if sink.file != nil {
		_ = sink.file.Close()
		_ = os.Remove(sink.path)
		sink.file = nil
	}
	if sink.metadataFile != nil {
		_ = sink.metadataFile.Close()
		sink.metadataFile = nil
		sink.metadataWrite = nil
	}
	if sink.metadataPath != "" {
		_ = os.Remove(sink.metadataPath)
		sink.metadataPath = ""
	}
}

var _ io.Writer = (*partSink)(nil)
