package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("add", addArgs{}, runAdd)
}

type addArgs struct{}

func (addArgs) Description() string {
	return "\nscan filesystem and stage new packs\n"
}

func runAdd() {
	var args addArgs
	arg.MustParse(&args)
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	err = backup.Add(config)
	if err != nil {
		panic(err)
	}
}
