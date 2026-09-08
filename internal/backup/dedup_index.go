package backup

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"backup/internal/format"
	"backup/internal/repository"
	"golang.org/x/sys/unix"
)

const dedupSlotBytes = 1 + 64 + 8

type dedupIndex struct {
	file     *os.File
	capacity uint64
	count    uint64
}

func newDedupIndex(path string, maximumEntries uint64) (*dedupIndex, error) {
	if maximumEntries > (uint64(^uint64(0)>>1)/dedupSlotBytes)/2 {
		return nil, fmt.Errorf("deduplication index is not representable")
	}
	capacity := uint64(2)
	needed := maximumEntries * 2
	for capacity < needed {
		if capacity > ^uint64(0)/2 {
			return nil, fmt.Errorf("deduplication index capacity overflow")
		}
		capacity *= 2
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	length := capacity * dedupSlotBytes
	if length > uint64(^uint64(0)>>1) {
		_ = file.Close()
		return nil, fmt.Errorf("deduplication index length is not representable")
	}
	if err := file.Truncate(int64(length)); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &dedupIndex{file: file, capacity: capacity}, nil
}

func (index *dedupIndex) Close() error {
	if index == nil || index.file == nil {
		return nil
	}
	err := index.file.Close()
	index.file = nil
	return err
}

func (index *dedupIndex) Insert(hash string, size uint64) error {
	found, slot, err := index.find(hash, size)
	if err != nil || found {
		return err
	}
	if index.count >= index.capacity/2 {
		return fmt.Errorf("deduplication index exceeded its planned load")
	}
	digest, err := decodeContentHash(hash)
	if err != nil {
		return err
	}
	var record [dedupSlotBytes]byte
	record[0] = 1
	copy(record[1:65], digest)
	binary.BigEndian.PutUint64(record[65:], size)
	if _, err := index.file.WriteAt(record[:], int64(slot*dedupSlotBytes)); err != nil {
		return err
	}
	index.count++
	return nil
}

func (index *dedupIndex) Contains(hash string, size uint64) (bool, error) {
	found, _, err := index.find(hash, size)
	return found, err
}

func (index *dedupIndex) find(hash string, size uint64) (bool, uint64, error) {
	if index == nil || index.file == nil || index.capacity < 2 {
		return false, 0, fmt.Errorf("deduplication index is closed")
	}
	digest, err := decodeContentHash(hash)
	if err != nil {
		return false, 0, err
	}
	hashed := sha256.Sum256(digest)
	start := binary.BigEndian.Uint64(hashed[:8]) & (index.capacity - 1)
	var record [dedupSlotBytes]byte
	for probe := uint64(0); probe < index.capacity; probe++ {
		slot := (start + probe) & (index.capacity - 1)
		if _, err := index.file.ReadAt(record[:], int64(slot*dedupSlotBytes)); err != nil {
			if err == io.EOF {
				return false, slot, nil
			}
			return false, 0, err
		}
		switch record[0] {
		case 0:
			return false, slot, nil
		case 1:
			if string(record[1:65]) != string(digest) {
				continue
			}
			storedSize := binary.BigEndian.Uint64(record[65:])
			if storedSize != size {
				return false, 0, fmt.Errorf("existing object %s has conflicting size", hash)
			}
			return true, slot, nil
		default:
			return false, 0, fmt.Errorf("deduplication index contains an invalid slot marker")
		}
	}
	return false, 0, fmt.Errorf("deduplication index has no empty slot")
}

func decodeContentHash(hash string) ([]byte, error) {
	if len(hash) != 128 || strings.ToLower(hash) != hash {
		return nil, fmt.Errorf("invalid plaintext BLAKE2b %q", hash)
	}
	digest, err := hex.DecodeString(hash)
	if err != nil || len(digest) != 64 {
		return nil, fmt.Errorf("invalid plaintext BLAKE2b %q", hash)
	}
	return digest, nil
}

func insertObjectCatalog(index *dedupIndex, reader io.Reader) (uint64, error) {
	var count uint64
	err := format.WalkObjects(reader, format.DefaultLimits(), func(entry format.ObjectEntry) error {
		if err := index.Insert(entry.PlaintextHash, entry.PlaintextSize); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

func (run *runtime) prepareCaptureDedup(path string, txn *transaction, base repository.State) (*dedupIndex, error) {
	if txn == nil || txn.Plan == nil || txn.Capture == nil || txn.Plan.Entries < 0 {
		return nil, fmt.Errorf("invalid capture state for deduplication index")
	}
	baseCount := base.ObjectCount
	planCount := uint64(txn.Plan.Entries)
	if ^uint64(0)-baseCount < planCount {
		return nil, fmt.Errorf("deduplication entry count overflow")
	}
	index, err := newDedupIndex(path, baseCount+planCount)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = index.Close()
		}
	}()
	if err := base.WalkObjects(format.DefaultLimits(), func(entry format.ObjectEntry) error {
		return index.Insert(entry.PlaintextHash, entry.PlaintextSize)
	}); err != nil {
		return nil, err
	}
	_, objectPaths, _, err := run.captureSegmentInputPaths(txn, false)
	if err != nil {
		return nil, err
	}
	for _, objectPath := range objectPaths {
		file, err := os.Open(objectPath)
		if err != nil {
			return nil, err
		}
		_, insertErr := insertObjectCatalog(index, file)
		closeErr := file.Close()
		if insertErr != nil {
			return nil, insertErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	keep = true
	return index, nil
}
