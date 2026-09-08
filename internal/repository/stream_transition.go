package repository

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/securefs"
)

func validateStreamTransition(oldState, newState State) (TransitionKind, error) {
	if err := oldState.Validate(); err != nil {
		return TransitionInvalid, fmt.Errorf("invalid parent state: %w", err)
	}
	if err := newState.Validate(); err != nil {
		return TransitionInvalid, fmt.Errorf("invalid child state: %w", err)
	}
	if !oldState.blobEqual(newState, "FORMAT") || oldState.Format != newState.Format {
		return TransitionInvalid, fmt.Errorf("FORMAT changed after genesis")
	}
	if statesEqual(oldState, newState) {
		return TransitionInvalid, fmt.Errorf("metadata transition has no changes")
	}
	workspace, err := os.MkdirTemp("", "backup-transition-validation-")
	if err != nil {
		return TransitionInvalid, err
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = securefs.RemoveTree(workspace)
		return TransitionInvalid, err
	}
	defer securefs.RemoveTree(workspace)
	if repair, err := isStreamRepairTransition(oldState, newState, workspace); repair || err != nil {
		if err != nil {
			return TransitionInvalid, err
		}
		return TransitionRepair, nil
	}
	if err := validateStreamOrdinaryExtension(oldState, newState, workspace); err != nil {
		return TransitionInvalid, err
	}
	if err := validateMirrorImmediateIdentity(oldState.Mirrors, newState.Mirrors); err != nil {
		return TransitionInvalid, err
	}
	return TransitionOrdinary, nil
}

func materializeStateBlob(state State, name, path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := state.withBlob(name, func(reader io.Reader) error {
		_, err := file.ReadFrom(reader)
		return err
	}); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func isStreamRepairTransition(oldState, newState State, workspace string) (bool, error) {
	for _, name := range RequiredBlobNames {
		if name != "packs.tsv" && !oldState.blobEqual(newState, name) {
			return false, nil
		}
	}
	oldPath, newPath := filepath.Join(workspace, "repair-old-packs"), filepath.Join(workspace, "repair-new-packs")
	if err := materializeStateBlob(oldState, "packs.tsv", oldPath); err != nil {
		return false, err
	}
	if err := materializeStateBlob(newState, "packs.tsv", newPath); err != nil {
		return false, err
	}
	oldRows, err := newDerivedRows(oldPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return false, err
	}
	defer oldRows.Close()
	newRows, err := newDerivedRows(newPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return false, err
	}
	defer newRows.Close()
	changed := uint64(0)
	for {
		oldNext, newNext := oldRows.Next(), newRows.Next()
		if !oldNext || !newNext {
			if oldNext != newNext {
				return false, fmt.Errorf("packs-only transition added or removed rows")
			}
			break
		}
		oldFields, newFields := oldRows.Fields(), newRows.Fields()
		if len(oldFields) != 8 || len(newFields) != 8 {
			return false, fmt.Errorf("invalid validated pack row")
		}
		for index := 0; index < 7; index++ {
			if oldFields[index] != newFields[index] {
				return false, fmt.Errorf("packs-only transition changed a logical pack field")
			}
		}
		if oldFields[7] != newFields[7] {
			changed++
		}
	}
	if err := errors.Join(oldRows.Err(), newRows.Err()); err != nil {
		return false, err
	}
	if changed == 0 {
		return false, fmt.Errorf("packs-only transition did not relocate any part")
	}
	return true, nil
}

func validateStreamOrdinaryExtension(oldState, newState State, workspace string) error {
	oldObjects := filepath.Join(workspace, "ordinary-old-objects")
	newObjects := filepath.Join(workspace, "ordinary-new-objects")
	oldPacks := filepath.Join(workspace, "ordinary-old-packs")
	newPacks := filepath.Join(workspace, "ordinary-new-packs")
	for _, item := range []struct {
		state State
		name  string
		path  string
	}{{oldState, "objects.tsv", oldObjects}, {newState, "objects.tsv", newObjects}, {oldState, "packs.tsv", oldPacks}, {newState, "packs.tsv", newPacks}} {
		if err := materializeStateBlob(item.state, item.name, item.path); err != nil {
			return err
		}
	}
	addedObjectPacks := filepath.Join(workspace, "added-object-packs")
	addedPackHashes := filepath.Join(workspace, "added-pack-hashes")
	objectOutput, err := os.OpenFile(addedObjectPacks, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := mergeCatalogExtension(oldObjects, newObjects, 3, func(fields []string) error {
		_, err := fmt.Fprintf(objectOutput, "%s\t%s\n", fields[2], fields[0])
		return err
	}, "object"); err != nil {
		objectOutput.Close()
		return err
	}
	if err := objectOutput.Close(); err != nil {
		return err
	}

	packOutput, err := os.OpenFile(addedPackHashes, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	oldRows, err := newDerivedRows(oldPacks, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		packOutput.Close()
		return err
	}
	defer oldRows.Close()
	newRows, err := newDerivedRows(newPacks, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		packOutput.Close()
		return err
	}
	defer newRows.Close()
	oldNext, newNext := oldRows.Next(), newRows.Next()
	var lastMatchedOldHash string
	for oldNext || newNext {
		if oldNext && len(oldRows.Fields()) != 8 || newNext && len(newRows.Fields()) != 8 {
			packOutput.Close()
			return fmt.Errorf("invalid validated pack row")
		}
		if !newNext {
			packOutput.Close()
			return fmt.Errorf("ordinary transition removed pack rows")
		}
		if oldNext {
			comparison := comparePackFields(oldRows.Fields(), newRows.Fields())
			switch {
			case comparison == 0:
				if !equalFields(oldRows.Fields(), newRows.Fields()) {
					packOutput.Close()
					return fmt.Errorf("ordinary transition altered pack row %s part %s", newRows.Fields()[0], newRows.Fields()[1])
				}
				lastMatchedOldHash = oldRows.Fields()[0]
				oldNext, newNext = oldRows.Next(), newRows.Next()
				continue
			case comparison < 0:
				packOutput.Close()
				return fmt.Errorf("ordinary transition removed pack rows")
			}
		}
		newFields := newRows.Fields()
		if newFields[0] == lastMatchedOldHash || oldNext && newFields[0] == oldRows.Fields()[0] {
			packOutput.Close()
			return fmt.Errorf("ordinary transition added parts to an existing pack %s", newFields[0])
		}
		if newFields[1] == "0" {
			if _, err := fmt.Fprintln(packOutput, newFields[0]); err != nil {
				packOutput.Close()
				return err
			}
		}
		newNext = newRows.Next()
	}
	if err := errors.Join(oldRows.Err(), newRows.Err(), packOutput.Close()); err != nil {
		return err
	}

	sortedObjectPacks := filepath.Join(workspace, "added-object-packs-sorted")
	firstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("derived record lacks key")
		}
		return field, nil
	}
	if err := extsort.SortFiles(workspace, []string{addedObjectPacks}, sortedObjectPacks, extsort.Options{Key: firstField, MaxLineBytes: format.DefaultLimits().MaxLineBytes}); err != nil {
		return err
	}
	if err := requireNewPackReferences(sortedObjectPacks, addedPackHashes); err != nil {
		return err
	}
	return nil
}

func mergeCatalogExtension(oldPath, newPath string, fieldCount int, added func([]string) error, label string) error {
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
		if oldNext && len(oldRows.Fields()) != fieldCount || newNext && len(newRows.Fields()) != fieldCount {
			return fmt.Errorf("invalid validated %s row", label)
		}
		if !newNext {
			return fmt.Errorf("ordinary transition removed %s rows", label)
		}
		if oldNext {
			switch comparison := bytes.Compare([]byte(oldRows.Fields()[0]), []byte(newRows.Fields()[0])); {
			case comparison == 0:
				if !equalFields(oldRows.Fields(), newRows.Fields()) {
					return fmt.Errorf("ordinary transition altered %s row %s", label, newRows.Fields()[0])
				}
				oldNext, newNext = oldRows.Next(), newRows.Next()
				continue
			case comparison < 0:
				return fmt.Errorf("ordinary transition removed %s rows", label)
			}
		}
		if err := added(newRows.Fields()); err != nil {
			return err
		}
		newNext = newRows.Next()
	}
	return errors.Join(oldRows.Err(), newRows.Err())
}

func comparePackFields(left, right []string) int {
	if comparison := bytes.Compare([]byte(left[0]), []byte(right[0])); comparison != 0 {
		return comparison
	}
	leftPart, _ := strconv.ParseUint(left[1], 10, 32)
	rightPart, _ := strconv.ParseUint(right[1], 10, 32)
	switch {
	case leftPart < rightPart:
		return -1
	case leftPart > rightPart:
		return 1
	default:
		return 0
	}
}

func equalFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func requireNewPackReferences(objectPacksPath, packHashesPath string) error {
	objects, err := newDerivedRows(objectPacksPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer objects.Close()
	packs, err := newDerivedRows(packHashesPath, format.DefaultLimits().MaxLineBytes)
	if err != nil {
		return err
	}
	defer packs.Close()
	objectNext, packNext := objects.Next(), packs.Next()
	for objectNext || packNext {
		if objectNext && len(objects.Fields()) != 2 || packNext && len(packs.Fields()) != 1 {
			return fmt.Errorf("invalid derived new-pack reference")
		}
		if !objectNext {
			return fmt.Errorf("new pack %s has no new object rows", packs.Fields()[0])
		}
		if !packNext || objects.Fields()[0] < packs.Fields()[0] {
			return fmt.Errorf("new object %s does not reference a newly added pack", objects.Fields()[1])
		}
		if objects.Fields()[0] > packs.Fields()[0] {
			return fmt.Errorf("new pack %s has no new object rows", packs.Fields()[0])
		}
		matched := objects.Fields()[0]
		for objectNext && objects.Fields()[0] == matched {
			objectNext = objects.Next()
		}
		packNext = packs.Next()
	}
	return errors.Join(objects.Err(), packs.Err())
}
