package filesystem

import (
	"fmt"

	"backup/internal/format"
)

type collectedScan struct {
	Result
	Index []format.IndexEntry
	Files []File
}

func scanForTest(root *Root, ignore format.Ignore, reporter Reporter) (collectedScan, error) {
	var collected collectedScan
	result, err := root.Walk(ignore, reporter, func(file *File, entry format.IndexEntry) error {
		collected.Index = append(collected.Index, entry)
		if file != nil {
			collected.Files = append(collected.Files, *file)
		}
		return nil
	})
	if err != nil {
		return collectedScan{}, err
	}
	collected.Result = result
	format.SortIndex(collected.Index)
	if _, err := format.MarshalIndex(collected.Index); err != nil {
		return collectedScan{}, fmt.Errorf("scanned index is invalid: %w", err)
	}
	return collected, nil
}
