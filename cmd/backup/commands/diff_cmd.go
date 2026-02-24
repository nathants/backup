package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"
	"fmt"
	"strconv"
	"strings"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("diff", diffArgs{}, runDiff)
}

type diffArgs struct{}

func (diffArgs) Description() string {
	return "\nshow staged diff\n"
}

func runDiff() {
	var args diffArgs
	arg.MustParse(&args)
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	diffs, err := backup.Diff(config)
	if err != nil {
		panic(err)
	}
	for _, diff := range diffs {
		switch diff.Kind {
		case backup.DiffAddition:
			fmt.Println("addition:\t" + formatEntry(diff.New))
		case backup.DiffDeletion:
			fmt.Println("deletion:\t" + formatEntry(diff.Old))
		case backup.DiffChange:
			fmt.Println("change:\t" + formatEntry(diff.New))
		default:
			panic("unknown diff kind")
		}
	}
}

func formatEntry(entry backup.IndexEntry) string {
	return strings.Join([]string{entry.Path, entry.Kind, entry.Ref, strconv.FormatInt(entry.Size, 10), entry.Mode}, "\t")
}
