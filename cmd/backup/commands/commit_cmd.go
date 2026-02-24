package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("commit", commitArgs{}, runCommit)
}

type commitArgs struct{}

func (commitArgs) Description() string {
	return "\ncommit staged packs\n"
}

func runCommit() {
	var args commitArgs
	arg.MustParse(&args)
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	err = backup.Commit(config)
	if err != nil {
		panic(err)
	}
}
