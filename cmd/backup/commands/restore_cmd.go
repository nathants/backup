package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"
	"fmt"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("restore", restoreArgs{}, runRestore)
}

type restoreArgs struct {
	Regex    string `arg:"positional"`
	Revision string `arg:"positional"`
	DryRun   bool   `arg:"--dry-run"`
}

func (restoreArgs) Description() string {
	return "\nrestore files matching regex\n"
}

func runRestore() {
	var args restoreArgs
	arg.MustParse(&args)
	if args.Regex == "" {
		panic("regex required")
	}
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	results, err := backup.Restore(config, args.Regex, args.Revision, args.DryRun)
	if err != nil {
		panic(err)
	}
	for _, line := range results {
		fmt.Println(line)
	}
}
