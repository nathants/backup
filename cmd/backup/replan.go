package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	backupapp "backup/internal/backup"
)

func runReplan(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("replan", flag.ContinueOnError)
	common := addCommon(flags)
	if err := parseFlags(flags, arguments, stdout, "[OPTIONS]", "Refresh an existing add plan using current ignore rules and directory traversal.\nDiscover newly eligible paths; hash only files without a saved regular-file observation.\nKnown content, size, mode, and mtime remain provisional, even when changed on disk.\nSymlinks are resolved afresh. Commit captures current content; add refreshes all observations.\nPreserves the saved base and --allow-empty choice, without fetching or uploading.\nOnly ignore may change; recipient/topology edits require add. Refuses commit progress."); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("replan accepts no positional arguments")
	}
	result, err := backupapp.Replan(ctx, common.options(stdout, stderr))
	if err != nil {
		return err
	}
	if err := printAddResult(stdout, result); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "reused-files\t%d\nhashed-files\t%d\nobservations\tprovisional\n", result.Scan.ReusedFiles, result.Scan.HashedFiles)
	return err
}
