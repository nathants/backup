package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	_ "backup/cmd/backup/commands"
	"backup/internal/cli"
	"github.com/alexflint/go-arg"
)

func usage() {
	fmt.Println("Usage:")
	var commandNames []string
	maxLen := 0
	for name := range cli.Commands {
		commandNames = append(commandNames, name)
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}
	sort.Strings(commandNames)
	fmtStr := "  backup %-" + fmt.Sprint(maxLen) + "s %s\n"
	for _, name := range commandNames {
		args := cli.Args[name]
		val := reflect.ValueOf(args)
		newVal := reflect.New(val.Type())
		newVal.Elem().Set(val)
		parser, err := arg.NewParser(arg.Config{}, newVal.Interface())
		if err != nil {
			fmt.Println("Error creating parser:", err)
			return
		}
		var buffer bytes.Buffer
		parser.WriteHelp(&buffer)
		line := ""
		for _, l := range strings.Split(buffer.String(), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "Usage:") {
				line = l
				break
			}
		}
		line = strings.ReplaceAll(line, "Usage: backup", "")
		fmt.Printf(fmtStr, name, line)
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(1)
	}
	command := os.Args[1]
	fn, ok := cli.Commands[command]
	if !ok {
		usage()
		fmt.Fprintln(os.Stderr, "\nunknown command:", command)
		os.Exit(1)
	}
	os.Args = os.Args[1:]
	fn()
}
