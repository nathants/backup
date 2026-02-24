package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("reset", resetArgs{}, runReset)
}

type resetArgs struct{}

func (resetArgs) Description() string {
	return "\nclear uncommitted state\n"
}

func runReset() {
	var args resetArgs
	arg.MustParse(&args)
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	err = backup.Reset(config)
	if err != nil {
		panic(err)
	}
}
