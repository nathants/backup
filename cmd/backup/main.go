package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	backupapp "backup/internal/backup"
	"backup/internal/format"
	"backup/internal/s3server"
	"golang.org/x/sys/unix"
)

const usageText = `usage: backup COMMAND [OPTIONS]

commands:
  init       prepare a new local repository (no network publication)
  add        scan and stage a snapshot
  diff       show the staged snapshot diff
  commit    publish the staged transaction
  reset      discard an unpublished transaction
  find       find snapshot paths by regular expression
  restore    restore selected paths safely
  verify     verify mirrors independently
  sync       copy a complete revision between mirrors
  repair     relocate a data part or republish a metadata edge immutably
  recover    recover metadata from one object mirror
  server     run the narrow production object server

restore safety:
  Keep exclusive control of the destination tree and its ancestry throughout
  restore; concurrent destination writers are unsupported, even as the same user.

common environment:
  BACKUP_ROOT             source root (default: /)
  BACKUP_CONFIG           trusted local config (default: $BACKUP_ROOT/.backup-config)
  BACKUP_SPOOL_DIRECTORY  trusted parent for private plaintext capture spools
  BACKUP_SECRET_KEY       64 lowercase hex recipient secret key for restore/recover
  BACKUP_SECRET_KEY_FILE  mode-0600 file containing that key
`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "backup:", escapeTerminal(err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 || arguments[0] == "help" || arguments[0] == "-h" || arguments[0] == "--help" {
		_, err := io.WriteString(stdout, usageText)
		return err
	}
	command, arguments := arguments[0], arguments[1:]
	var err error
	switch command {
	case "init":
		err = runInit(ctx, arguments, stdout, stderr)
	case "add":
		err = runAdd(ctx, arguments, stdout, stderr)
	case "diff":
		err = runDiff(arguments, stdout, stderr)
	case "commit":
		err = runCommit(ctx, arguments, stdout, stderr)
	case "reset":
		err = runReset(arguments, stdout, stderr)
	case "find":
		err = runFind(arguments, stdout, stderr)
	case "restore":
		err = runRestore(ctx, arguments, stdout, stderr)
	case "verify":
		err = runVerify(ctx, arguments, stdout, stderr)
	case "sync":
		err = runSync(ctx, arguments, stdout, stderr)
	case "repair":
		err = runRepair(ctx, arguments, stdout, stderr)
	case "recover":
		err = runRecover(ctx, arguments, stdout, stderr)
	case "server":
		err = runServer(ctx, arguments, stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	if errors.Is(err, flag.ErrHelp) {
		_, writeErr := io.WriteString(stdout, usageText)
		return writeErr
	}
	return err
}

type commonFlags struct {
	root         string
	config       string
	spool        string
	spaceReserve uint64
}

func addCommon(flags *flag.FlagSet) *commonFlags {
	defaults := &commonFlags{root: os.Getenv("BACKUP_ROOT"), config: os.Getenv("BACKUP_CONFIG"), spool: os.Getenv("BACKUP_SPOOL_DIRECTORY")}
	if defaults.root == "" {
		defaults.root = "/"
	}
	flags.StringVar(&defaults.root, "root", defaults.root, "backup source root")
	flags.StringVar(&defaults.config, "config", defaults.config, "trusted local config file")
	flags.StringVar(&defaults.spool, "spool-directory", defaults.spool, "trusted parent for private plaintext capture spools")
	flags.Uint64Var(&defaults.spaceReserve, "space-reserve-bytes", 0, "minimum free bytes retained on staging filesystems")
	return defaults
}

func (common *commonFlags) options(stdout, stderr io.Writer) backupapp.Options {
	return backupapp.Options{
		Root: common.root, ConfigPath: common.config, SpoolDirectory: common.spool,
		SpaceReserveBytes: common.spaceReserve, Stdout: stdout, Stderr: stderr,
	}
}

func parseFlags(flags *flag.FlagSet, arguments []string) error {
	flags.SetOutput(io.Discard)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	return nil
}

func runInit(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	common := addCommon(flags)
	var recovery, publicKeysFile string
	flags.StringVar(&recovery, "recovery-public-key", "", "permanent recovery public key (64 lowercase hex)")
	flags.StringVar(&publicKeysFile, "public-keys", "", "canonical public-key list file")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || recovery == "" {
		return fmt.Errorf("init requires --recovery-public-key and no positional arguments")
	}
	recoveryKey, err := decodePublicKey(recovery)
	if err != nil {
		return err
	}
	keys := [][]byte{recoveryKey}
	if publicKeysFile != "" {
		file, err := os.Open(publicKeysFile)
		if err != nil {
			return err
		}
		limits := format.DefaultLimits()
		limits.MaxFileBytes = format.MaximumPublicKeysBytes
		keys, err = format.ParsePublicKeys(file, limits)
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	result, err := backupapp.Init(ctx, common.options(stdout, stderr), backupapp.InitRequest{PublicKeys: keys, RecoveryPublicKey: recoveryKey})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "initialized\t%s\npublication\tlocal-only\n", result.RepositoryUUID)
	return err
}

func runAdd(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	common := addCommon(flags)
	allowEmpty := flags.Bool("allow-empty", false, "permit a zero-entry snapshot")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("add accepts no positional arguments")
	}
	result, err := backupapp.Add(ctx, common.options(stdout, stderr), *allowEmpty)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "base\t%s\nentries\t%d\nnew-objects\t%d\nnew-packs\t%d\nno-changes\t%t\n", result.BaseCommit, result.Entries, result.UniqueNewObjects, result.NewPacks, result.NoChanges); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "skipped-special\t%d\nskipped-broken-symlinks\t%d\nskipped-outside-symlinks\t%d\nmounts-entered\t%d\n", result.Scan.SkippedSpecial, result.Scan.SkippedBrokenSymlinks, result.Scan.SkippedOutsideSymlinks, result.Scan.MountsEntered)
	return err
}

func runDiff(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	common := addCommon(flags)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("diff accepts no positional arguments")
	}
	_, err := backupapp.DiffCandidate(common.options(stdout, stderr), func(diff backupapp.Diff) error {
		entry := diff.New
		if entry == nil {
			entry = diff.Old
		}
		_, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%d\n", diff.Kind, escapeTerminal(entry.Path), entry.Kind, escapeTerminal(entry.Ref), entry.Size)
		return err
	})
	return err
}

func runCommit(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("commit", flag.ContinueOnError)
	common := addCommon(flags)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("commit accepts no positional arguments")
	}
	result, err := backupapp.Commit(ctx, common.options(stdout, stderr))
	if err != nil {
		return err
	}
	return printSnapshotResult(stdout, result)
}

func printSnapshotResult(output io.Writer, result backupapp.SnapshotResult) error {
	if _, err := fmt.Fprintf(output, "commit\t%s\nno-changes\t%t\n", result.CommitID, result.NoChanges); err != nil {
		return err
	}
	for _, mirror := range result.CompleteMirrors {
		if _, err := fmt.Fprintf(output, "complete-mirror\t%s\n", mirror); err != nil {
			return err
		}
	}
	for _, mirror := range result.LaggingMirrors {
		if _, err := fmt.Fprintf(output, "lagging-mirror\t%s\n", mirror); err != nil {
			return err
		}
	}
	return nil
}

func runReset(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("reset", flag.ContinueOnError)
	common := addCommon(flags)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("reset accepts no positional arguments")
	}
	if err := backupapp.Reset(common.options(stdout, stderr)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "reset")
	return err
}

func runFind(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("find", flag.ContinueOnError)
	common := addCommon(flags)
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() < 1 || flags.NArg() > 2 {
		return fmt.Errorf("find requires REGEX and optional REVISION")
	}
	revision := ""
	if flags.NArg() == 2 {
		revision = flags.Arg(1)
	}
	_, err := backupapp.Find(common.options(stdout, stderr), flags.Arg(0), revision, func(commit string) error {
		_, err := fmt.Fprintf(stdout, "commit\t%s\n", commit)
		return err
	}, func(entry format.IndexEntry) error {
		_, err := fmt.Fprintf(stdout, "%s\t%s\t%s\t%d\t%04o\t%d\n", escapeTerminal(entry.Path), entry.Kind, escapeTerminal(entry.Ref), entry.Size, entry.Mode, entry.MtimeNS)
		return err
	})
	return err
}

func runRestore(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	common := addCommon(flags)
	request := backupapp.RestoreRequest{}
	flags.StringVar(&request.CatalogRevision, "catalog-revision", "", "descendant catalog revision for immutable relocation")
	flags.StringVar(&request.TargetRoot, "target", "", "existing restore target directory")
	flags.BoolVar(&request.DryRun, "dry-run", false, "plan without object reads or writes")
	flags.BoolVar(&request.Overwrite, "overwrite", false, "replace compatible existing leaves")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() < 1 || flags.NArg() > 2 {
		return fmt.Errorf("restore requires REGEX and optional REVISION")
	}
	request.Pattern = flags.Arg(0)
	if flags.NArg() == 2 {
		request.Revision = flags.Arg(1)
	}
	request.Report = func(event backupapp.RestoreEvent) error {
		var err error
		switch event.Kind {
		case backupapp.RestoreResolved:
			_, err = fmt.Fprintf(stdout, "snapshot-commit\t%s\ncatalog-commit\t%s\n", event.SnapshotCommit, event.CatalogCommit)
		case backupapp.RestorePlanned:
			_, err = fmt.Fprintf(stdout, "plan\t%s\t%s\t%s\n", event.Status, event.FilesystemKind, escapeTerminal(event.Path))
		case backupapp.RestorePublished:
			_, err = fmt.Fprintf(stdout, "published\t%s\n", escapeTerminal(event.Path))
		case backupapp.RestoreRemaining:
			_, err = fmt.Fprintf(stdout, "remaining\t%s\n", escapeTerminal(event.Path))
		default:
			return fmt.Errorf("unknown restore event %q", event.Kind)
		}
		return err
	}
	_, err := backupapp.Restore(ctx, common.options(stdout, stderr), request)
	return err
}

func runVerify(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	common := addCommon(flags)
	minimum := flags.Int("minimum-mirrors", 1, "required independently healthy mirrors")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return fmt.Errorf("verify accepts optional REVISION")
	}
	revision := ""
	if flags.NArg() == 1 {
		revision = flags.Arg(0)
	}
	result, operationErr := backupapp.Verify(ctx, common.options(stdout, stderr), *minimum, revision)
	_, outputErr := fmt.Fprintf(stdout, "commit\t%s\npassed\t%d\nminimum\t%d\n", result.CommitID, result.Passed, result.Minimum)
	for _, mirror := range result.Mirrors {
		if outputErr != nil {
			break
		}
		if mirror.Complete {
			_, outputErr = fmt.Fprintf(stdout, "mirror\t%s\tcomplete\n", mirror.Name)
		} else {
			_, outputErr = fmt.Fprintf(stdout, "mirror\t%s\tfailed\t%s\n", mirror.Name, mirror.Error)
		}
	}
	return errors.Join(operationErr, outputErr)
}

func runSync(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sync", flag.ContinueOnError)
	common := addCommon(flags)
	source := flags.String("source", "", "healthy source mirror")
	destination := flags.String("destination", "", "destination mirror")
	revision := flags.String("revision", "", "revision to synchronize")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("sync accepts no positional arguments")
	}
	result, err := backupapp.Sync(ctx, common.options(stdout, stderr), *source, *destination, *revision)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "commit\t%s\nsource\t%s\ndestination\t%s\ndata-copied\t%d\nmetadata-copied\t%d\n", result.CommitID, result.Source, result.Destination, result.DataCopied, result.MetadataCopied)
	return err
}

func runRepair(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 1 && (arguments[0] == "-h" || arguments[0] == "--help") {
		return flag.ErrHelp
	}
	if len(arguments) == 0 {
		return fmt.Errorf("repair requires data or metadata subcommand")
	}
	switch arguments[0] {
	case "data":
		return runRepairData(ctx, arguments[1:], stdout, stderr)
	case "metadata":
		return runRepairMetadata(ctx, arguments[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown repair subcommand %q", arguments[0])
	}
}

func runRepairData(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("repair data", flag.ContinueOnError)
	common := addCommon(flags)
	source := flags.String("source", "", "healthy source mirror")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 2 || *source == "" {
		return fmt.Errorf("repair data requires PACK_HASH PART_NUMBER and --source")
	}
	part, err := strconv.ParseUint(flags.Arg(1), 10, 32)
	if err != nil || strconv.FormatUint(part, 10) != flags.Arg(1) {
		return fmt.Errorf("part number must be canonical unsigned decimal")
	}
	result, err := backupapp.RepairDataPart(ctx, common.options(stdout, stderr), *source, flags.Arg(0), uint32(part))
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "commit\t%s\npack\t%s\npart\t%d\nold-object-id\t%s\nnew-object-id\t%s\n", result.CommitID, result.PackHash, result.PartNumber, result.OldObjectID, result.NewObjectID); err != nil {
		return err
	}
	for _, mirror := range result.CompleteMirrors {
		if _, err := fmt.Fprintf(stdout, "complete-mirror\t%s\n", mirror); err != nil {
			return err
		}
	}
	return nil
}

func runRepairMetadata(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("repair metadata", flag.ContinueOnError)
	common := addCommon(flags)
	destination := flags.String("destination", "", "mirror receiving the alternate representation")
	revision := flags.String("revision", "", "exact metadata revision to republish (default HEAD)")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *destination == "" {
		return fmt.Errorf("repair metadata requires --destination and optional --revision")
	}
	result, err := backupapp.RepairMetadataEdge(ctx, common.options(stdout, stderr), *destination, *revision)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "tip\t%s\nmanifest-hash\t%s\nmanifest-object-id\t%s\nparts\t%d\n", result.TipCommit, result.ManifestHash, result.ManifestObjectID, result.Parts)
	return err
}

func runRecover(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	common := addCommon(flags)
	request := backupapp.RecoverRequest{}
	flags.StringVar(&request.Mirror, "mirror", "", "mirror to recover from")
	flags.StringVar(&request.Tip, "tip", "", "exact externally anchored commit")
	flags.StringVar(&request.Destination, "destination", "", "new bare repository destination")
	flags.BoolVar(&request.ListOnly, "list", false, "list candidate tips only")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("recover accepts no positional arguments")
	}
	request.Report = func(event backupapp.RecoverEvent) error {
		_, err := fmt.Fprintf(stdout, "available-tip\t%s\n", event.AvailableTip)
		return err
	}
	result, operationErr := backupapp.Recover(ctx, common.options(stdout, stderr), request)
	return errors.Join(operationErr, printRecoverResult(stdout, result))
}

func printRecoverResult(output io.Writer, result backupapp.RecoverResult) error {
	if result.RecoveredTip == "" {
		return nil
	}
	_, err := fmt.Fprintf(output, "recovered-tip\t%s\ndestination\t%s\n", result.RecoveredTip, escapeTerminal(result.Destination))
	return err
}

func decodePublicKey(value string) ([]byte, error) {
	if len(value) != 64 || strings.ToLower(value) != value {
		return nil, fmt.Errorf("public key must be 64 lowercase hexadecimal characters")
	}
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("public key must be 64 lowercase hexadecimal characters")
	}
	return key, nil
}

func loadServerCertificate(certificatePath, privateKeyPath string) (tls.Certificate, error) {
	certificatePEM, err := readTLSFile(certificatePath, false)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS certificate: %w", err)
	}
	privateKeyPEM, err := readTLSFile(privateKeyPath, true)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read TLS private key: %w", err)
	}
	defer func() {
		for index := range privateKeyPEM {
			privateKeyPEM[index] = 0
		}
	}()
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse TLS certificate and private key: %w", err)
	}
	return certificate, nil
}

func readTLSFile(path string, private bool) ([]byte, error) {
	const maximumTLSFileBytes = int64(4 << 20)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumTLSFileBytes {
		return nil, fmt.Errorf("file must be a nonempty bounded regular file")
	}
	if private && (info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0) {
		return nil, fmt.Errorf("private-key file must have mode 0600 or stricter")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumTLSFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("file size changed while reading")
	}
	return data, nil
}

func runServer(parent context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := flags.String("listen", ":8443", "HTTPS listen address")
	root := flags.String("data-root", "", "private object data root")
	bucket := flags.String("bucket", "", "single served bucket")
	prefix := flags.String("prefix", "", "single served backup prefix")
	region := flags.String("region", "us-east-1", "SigV4 region")
	certificate := flags.String("tls-cert", "", "TLS certificate file")
	privateKey := flags.String("tls-key", "", "TLS private-key file")
	if err := parseFlags(flags, arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *root == "" || *bucket == "" || *certificate == "" || *privateKey == "" {
		return fmt.Errorf("server requires --data-root, --bucket, --tls-cert, and --tls-key")
	}
	access := os.Getenv("BACKUP_SERVER_ACCESS_KEY")
	secret := os.Getenv("BACKUP_SERVER_SECRET_KEY")
	if access == "" || secret == "" {
		return fmt.Errorf("BACKUP_SERVER_ACCESS_KEY and BACKUP_SERVER_SECRET_KEY are required")
	}
	tlsCertificate, err := loadServerCertificate(*certificate, *privateKey)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	backend, err := s3server.Open(s3server.Config{
		Root: *root, Bucket: *bucket, Prefix: *prefix, Region: *region, Logger: logger,
		Credential: s3server.Credential{AccessKey: access, SecretKey: secret, SessionToken: os.Getenv("BACKUP_SERVER_SESSION_TOKEN")},
	})
	if err != nil {
		return err
	}
	defer func() { _ = backend.Close() }()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{
		Handler:           backend,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsCertificate}},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       24 * time.Hour,
		WriteTimeout:      24 * time.Hour,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if _, err := fmt.Fprintln(stdout, listener.Addr().String()); err != nil {
		return err
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ServeTLS(listener, "", "") }()
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		return nil
	}
}

func escapeTerminal(value string) string {
	control := regexp.MustCompile(`[\x00-\x1f\x7f]`)
	return control.ReplaceAllStringFunc(value, func(value string) string { return fmt.Sprintf("\\x%02x", value[0]) })
}
