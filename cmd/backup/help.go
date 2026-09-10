package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
)

const restoreSafetyText = `restore safety:
  Keep exclusive control of the destination tree and its ancestry throughout
  restore; concurrent destination writers are unsupported, even as the same user.`

const resourceSafetyText = `untrusted-backup safety:
  For potentially malicious backups, enforce aggregate memory/swap, CPU/time,
  and storage byte/inode limits for this command and all its descendants.
  Cover temporary and destination storage, including TMPDIR; the binary does
  not enforce these resource limits.`

const decryptionHelpText = `decryption:
  Configure exactly one nonempty GIT_REMOTE_AWS_SECRETKEY,
  GIT_REMOTE_AWS_SECRETKEY_FILE, or GIT_REMOTE_AWS_SECRETKEY_CMD source with an
  eligible recipient secret chain.`

const repairUsageText = `usage: backup repair {data|metadata} [OPTIONS]

commands:
  data       relocate healthy exact ciphertext through an immutable Git revision
  metadata   publish an alternate immutable representation of a metadata edge

Use backup repair data --help for PACK_HASH, PART_NUMBER, and source options.
Use backup repair metadata --help for destination and revision options.
Repairs never overwrite or delete existing objects.
`

func parseFlags(flags *flag.FlagSet, arguments []string, stdout io.Writer, synopsis, description string) error {
	// Parse errors remain concise errors for main to escape and print. Only an
	// explicit help request emits usage, before any command operation starts.
	flags.SetOutput(io.Discard)
	if err := flags.Parse(arguments); !errors.Is(err, flag.ErrHelp) {
		return err
	}
	// PrintDefaults does not return write errors. Render into memory first so
	// the final stdout write can report a broken pipe or short write normally.
	var help bytes.Buffer
	fmt.Fprintf(&help, "usage: backup %s %s\n\n%s\n\noptions (before positional arguments):\n", flags.Name(), synopsis, description)
	flags.SetOutput(&help)
	flags.PrintDefaults()
	if _, err := help.WriteTo(stdout); err != nil {
		return fmt.Errorf("write help: %w", err)
	}
	return flag.ErrHelp
}
