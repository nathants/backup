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
	cli.Register("find", findArgs{}, runFind)
}

type findArgs struct {
	Regex    string `arg:"positional"`
	Revision string `arg:"positional"`
}

func (findArgs) Description() string {
	return "\nfind files matching regex at revision\n"
}

func runFind() {
	var args findArgs
	arg.MustParse(&args)
	if args.Regex == "" {
		panic("regex required")
	}
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	entries, err := backup.Find(config, args.Regex, args.Revision)
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		fmt.Println(strings.Join([]string{entry.Path, entry.Kind, entry.Ref, strconv.FormatInt(entry.Size, 10), entry.Mode}, "\t"))
	}
}
