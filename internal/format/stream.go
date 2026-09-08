package format

import (
	"fmt"
	"io"
	"strconv"
)

// MarshalIndexEntry returns one complete canonical LF-terminated index row.
func MarshalIndexEntry(entry IndexEntry) ([]byte, error) {
	row, err := entry.row()
	if err != nil {
		return nil, err
	}
	return marshalRows([][]string{row})
}

// MarshalObjectEntry returns one complete canonical LF-terminated object row.
func MarshalObjectEntry(entry ObjectEntry) ([]byte, error) {
	if err := validateObjectEntry(entry); err != nil {
		return nil, err
	}
	return marshalRows([][]string{{entry.PlaintextHash, uintText(entry.PlaintextSize), entry.PackHash}})
}

// MarshalPackEntry returns one complete canonical LF-terminated pack row.
func MarshalPackEntry(entry PackEntry) ([]byte, error) {
	row, err := entry.row()
	if err != nil {
		return nil, err
	}
	return marshalRows([][]string{row})
}

// WalkIndex validates each row and sorted uniqueness while retaining only one
// record. Cross-row leaf/ancestor validation is deliberately performed by the
// catalog validator, which can use bounded external workspace.
func WalkIndex(reader io.Reader, limits Limits, visit func(IndexEntry) error) error {
	var previous string
	err := scanRows(reader, limits, func(record int, row []string) error {
		entry, err := parseIndexRow(record, row)
		if err != nil {
			return err
		}
		if previous != "" && previous >= entry.Path {
			return fmt.Errorf("paths are not sorted uniquely at record %d", record)
		}
		previous = entry.Path
		if visit != nil {
			return visit(entry)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("index.tsv: %w", err)
	}
	return nil
}

func parseIndexRow(record int, row []string) (IndexEntry, error) {
	if err := requireFieldCount(row, 6, record); err != nil {
		return IndexEntry{}, err
	}
	size, err := parseUint(row[3], 64, "size")
	if err != nil {
		return IndexEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	entry := IndexEntry{Path: row[0], Kind: row[1], Ref: row[2], Size: size}
	switch row[1] {
	case KindFile:
		if len(row[4]) != 4 || row[4][0] != '0' {
			return IndexEntry{}, fmt.Errorf("record %d has noncanonical mode %q", record, row[4])
		}
		mode, parseErr := strconv.ParseUint(row[4], 8, 12)
		if parseErr != nil || mode > 0o777 {
			return IndexEntry{}, fmt.Errorf("record %d has invalid mode %q", record, row[4])
		}
		mtime, parseErr := parseInt64(row[5], "mtime_ns")
		if parseErr != nil {
			return IndexEntry{}, fmt.Errorf("record %d: %w", record, parseErr)
		}
		entry.Mode = uint32(mode)
		entry.MtimeNS = mtime
	case KindSymlink:
		if row[4] != "-" || row[5] != "-" {
			return IndexEntry{}, fmt.Errorf("record %d has file metadata on a symlink", record)
		}
	default:
		return IndexEntry{}, fmt.Errorf("record %d has unknown kind %q", record, row[1])
	}
	if err := validateIndexEntry(entry); err != nil {
		return IndexEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	return entry, nil
}

// WalkObjects validates an objects table with constant retained state.
func WalkObjects(reader io.Reader, limits Limits, visit func(ObjectEntry) error) error {
	var previous string
	err := scanRows(reader, limits, func(record int, row []string) error {
		entry, err := parseObjectRow(record, row)
		if err != nil {
			return err
		}
		if previous != "" && previous >= entry.PlaintextHash {
			return fmt.Errorf("not sorted uniquely at record %d", record)
		}
		previous = entry.PlaintextHash
		if visit != nil {
			return visit(entry)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("objects.tsv: %w", err)
	}
	return nil
}

func parseObjectRow(record int, row []string) (ObjectEntry, error) {
	if err := requireFieldCount(row, 3, record); err != nil {
		return ObjectEntry{}, err
	}
	size, err := parseUint(row[1], 64, "plaintext size")
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	entry := ObjectEntry{PlaintextHash: row[0], PlaintextSize: size, PackHash: row[2]}
	if err := validateObjectEntry(entry); err != nil {
		return ObjectEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	return entry, nil
}

// WalkPacks validates pack order, contiguity, and terminal part counts while
// retaining only the previous row.
func WalkPacks(reader io.Reader, limits Limits, visit func(PackEntry) error) error {
	var previous PackEntry
	havePrevious := false
	err := scanRows(reader, limits, func(record int, row []string) error {
		entry, err := parsePackRow(record, row)
		if err != nil {
			return err
		}
		if !havePrevious || previous.PackHash != entry.PackHash {
			if havePrevious {
				if previous.PartNumber+1 != previous.PartCount {
					return fmt.Errorf("pack %s is missing terminal parts", previous.PackHash)
				}
				if previous.PackHash >= entry.PackHash {
					return fmt.Errorf("packs are not sorted uniquely")
				}
			}
			if entry.PartNumber != 0 {
				return fmt.Errorf("pack %s starts at part %d", entry.PackHash, entry.PartNumber)
			}
		} else if entry.PartCount != previous.PartCount || entry.PartNumber != previous.PartNumber+1 {
			return fmt.Errorf("pack %s has inconsistent or noncontiguous parts", entry.PackHash)
		}
		previous, havePrevious = entry, true
		if visit != nil {
			return visit(entry)
		}
		return nil
	})
	if err == nil && havePrevious && previous.PartNumber+1 != previous.PartCount {
		err = fmt.Errorf("pack %s is missing terminal parts", previous.PackHash)
	}
	if err != nil {
		return fmt.Errorf("packs.tsv: %w", err)
	}
	return nil
}

func parsePackRow(record int, row []string) (PackEntry, error) {
	if err := requireFieldCount(row, 8, record); err != nil {
		return PackEntry{}, err
	}
	partNumber, err := parseUint(row[1], 32, "part number")
	if err != nil {
		return PackEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	partCount, err := parseUint(row[2], 32, "part count")
	if err != nil {
		return PackEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	partSize, err := parseUint(row[6], 64, "part size")
	if err != nil {
		return PackEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	entry := PackEntry{PackHash: row[0], PartNumber: uint32(partNumber), PartCount: uint32(partCount), PartHash: row[3], PartSHA256: row[4], PartMD5: row[5], PartSize: partSize, ObjectID: row[7]}
	if err := validatePackEntry(entry); err != nil {
		return PackEntry{}, fmt.Errorf("record %d: %w", record, err)
	}
	return entry, nil
}
