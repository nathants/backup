package commands

import (
	"backup/internal/backup"
	"backup/internal/cli"
	"fmt"

	"github.com/alexflint/go-arg"
)

func init() {
	cli.Register("init", initArgs{}, runInit)
}

type initArgs struct{}

func (initArgs) Description() string {
	return "\ninitialize backup repo\n"
}

func runInit() {
	var args initArgs
	arg.MustParse(&args)
	config, err := backup.LoadConfig(backup.Requirements{NeedRoot: true, NeedGit: true, NeedS3: true})
	if err != nil {
		panic(err)
	}
	err = backup.InitRepo(config)
	if err != nil {
		panic(fmt.Errorf("init failed: %w", err))
	}
}
