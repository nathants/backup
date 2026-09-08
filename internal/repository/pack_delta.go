package repository

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"backup/internal/format"
	"backup/internal/securefs"
)

// WalkChangedPacks visits exactly the candidate pack rows introduced or
// relocated by the declared transition. Both catalogs are streamed through
// bounded private workspace.
func WalkChangedPacks(base, candidate State, transition TransitionKind, visit func(format.PackEntry) error) error {
	if visit == nil {
		return fmt.Errorf("changed-pack visitor is required")
	}
	if transition == TransitionInvalid {
		return candidate.WalkPacks(format.DefaultLimits(), visit)
	}
	workspace, err := os.MkdirTemp("", "backup-pack-delta-")
	if err != nil {
		return err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = securefs.RemoveTree(workspace)
		return err
	}
	defer securefs.RemoveTree(workspace)
	oldPath, newPath := filepath.Join(workspace, "old"), filepath.Join(workspace, "new")
	if err := materializeStateBlob(base, "packs.tsv", oldPath); err != nil {
		return err
	}
	if err := materializeStateBlob(candidate, "packs.tsv", newPath); err != nil {
		return err
	}
	oldRows, err := newDerivedRows(oldPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer oldRows.Close()
	newRows, err := newDerivedRows(newPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer newRows.Close()
	oldNext, newNext := oldRows.Next(), newRows.Next()
	for oldNext || newNext {
		if !newNext {
			return fmt.Errorf("candidate removed pack rows")
		}
		if len(newRows.Fields()) != 8 || oldNext && len(oldRows.Fields()) != 8 {
			return fmt.Errorf("invalid validated pack row")
		}
		if oldNext {
			comparison := comparePackFields(oldRows.Fields(), newRows.Fields())
			switch {
			case comparison == 0:
				changed := !equalFields(oldRows.Fields(), newRows.Fields())
				if transition == TransitionOrdinary && changed {
					return fmt.Errorf("ordinary candidate altered a pack row")
				}
				if transition == TransitionRepair && changed {
					entry, err := packEntryFromFields(newRows.Fields())
					if err != nil {
						return err
					}
					if err := visit(entry); err != nil {
						return err
					}
				}
				oldNext, newNext = oldRows.Next(), newRows.Next()
				continue
			case comparison < 0:
				return fmt.Errorf("candidate removed pack rows")
			}
		}
		if transition != TransitionOrdinary {
			return fmt.Errorf("repair candidate added pack rows")
		}
		entry, err := packEntryFromFields(newRows.Fields())
		if err != nil {
			return err
		}
		if err := visit(entry); err != nil {
			return err
		}
		newNext = newRows.Next()
	}
	return errors.Join(oldRows.Err(), newRows.Err())
}

func FindPackPart(state State, packHash string, partNumber uint32) (format.PackEntry, bool, error) {
	var found format.PackEntry
	err := state.WalkPacks(format.DefaultLimits(), func(entry format.PackEntry) error {
		if entry.PackHash == packHash && entry.PartNumber == partNumber {
			found = entry
		}
		return nil
	})
	return found, found.PackHash != "", err
}

// ValidateCatalogStateForSnapshot permits only object-ID relocations for every
// pack row reachable from the snapshot. Later unrelated rows are harmless.
func ValidateCatalogStateForSnapshot(snapshot, alternate State) error {
	workspace, err := os.MkdirTemp("", "backup-catalog-compatibility-")
	if err != nil {
		return err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = securefs.RemoveTree(workspace)
		return err
	}
	defer securefs.RemoveTree(workspace)
	snapshotPath, alternatePath := filepath.Join(workspace, "snapshot"), filepath.Join(workspace, "alternate")
	if err := materializeStateBlob(snapshot, "packs.tsv", snapshotPath); err != nil {
		return err
	}
	if err := materializeStateBlob(alternate, "packs.tsv", alternatePath); err != nil {
		return err
	}
	left, err := newDerivedRows(snapshotPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer left.Close()
	right, err := newDerivedRows(alternatePath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer right.Close()
	leftNext, rightNext := left.Next(), right.Next()
	for leftNext {
		if len(left.Fields()) != 8 {
			return fmt.Errorf("invalid validated snapshot pack row")
		}
		for rightNext && comparePackFields(right.Fields(), left.Fields()) < 0 {
			rightNext = right.Next()
		}
		if !rightNext || len(right.Fields()) != 8 || comparePackFields(right.Fields(), left.Fields()) != 0 {
			return fmt.Errorf("alternate catalog lacks pack %s part %s", left.Fields()[0], left.Fields()[1])
		}
		for index := 0; index < 7; index++ {
			if left.Fields()[index] != right.Fields()[index] {
				return fmt.Errorf("alternate catalog changes immutable fields for pack %s part %s", left.Fields()[0], left.Fields()[1])
			}
		}
		leftNext = left.Next()
		rightNext = right.Next()
	}
	return errors.Join(left.Err(), right.Err())
}

func packEntryFromFields(fields []string) (format.PackEntry, error) {
	if len(fields) != 8 {
		return format.PackEntry{}, fmt.Errorf("invalid validated pack row")
	}
	partNumber, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return format.PackEntry{}, err
	}
	partCount, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return format.PackEntry{}, err
	}
	partSize, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return format.PackEntry{}, err
	}
	return format.PackEntry{
		PackHash: fields[0], PartNumber: uint32(partNumber), PartCount: uint32(partCount),
		PartHash: fields[3], PartSHA256: fields[4], PartMD5: fields[5], PartSize: partSize, ObjectID: fields[7],
	}, nil
}
