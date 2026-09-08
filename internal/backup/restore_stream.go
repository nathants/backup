package backup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/pack"
	"backup/internal/repository"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const restoreDerivedLineBytes = 1024

type restoreSelection struct {
	directory             string
	regularIndex          string
	symlinkIndex          string
	selectedHashesRaw     string
	selectedHashes        string
	allObjectsByPack      string
	selectedObjectsByPack string
	neededPacks           string
	regularCount          uint64
}

type restoreOutput struct {
	file   *os.File
	writer *bufio.Writer
	closed bool
}

func createRestoreOutput(path string) (*restoreOutput, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &restoreOutput{file: file, writer: bufio.NewWriterSize(file, 256<<10)}, nil
}

func (output *restoreOutput) Write(data []byte) error {
	if output == nil || output.closed {
		return fmt.Errorf("restore workspace output is closed")
	}
	_, err := output.writer.Write(data)
	return err
}

func (output *restoreOutput) Printf(pattern string, values ...any) error {
	if output == nil || output.closed {
		return fmt.Errorf("restore workspace output is closed")
	}
	_, err := fmt.Fprintf(output.writer, pattern, values...)
	return err
}

func (output *restoreOutput) Close() error {
	if output == nil || output.closed {
		return nil
	}
	output.closed = true
	flushErr := output.writer.Flush()
	var syncErr error
	if flushErr == nil {
		syncErr = output.file.Sync()
	}
	return errors.Join(flushErr, syncErr, output.file.Close())
}

func (output *restoreOutput) Abort() {
	if output == nil || output.closed {
		return
	}
	output.closed = true
	_ = output.file.Close()
}

func planRestoreSelection(snapshot repository.State, expression interface{ MatchString(string) bool }, targetFD int, overwrite bool, directory string, report func(RestoreEvent) error, result *RestoreResult) (_ restoreSelection, conflicts bool, returnErr error) {
	selection := restoreSelection{
		directory:             directory,
		regularIndex:          filepath.Join(directory, "selected-regular.index"),
		symlinkIndex:          filepath.Join(directory, "selected-symlinks.index"),
		selectedHashesRaw:     filepath.Join(directory, "selected-hashes.raw"),
		selectedHashes:        filepath.Join(directory, "selected-hashes"),
		allObjectsByPack:      filepath.Join(directory, "all-objects-by-pack"),
		selectedObjectsByPack: filepath.Join(directory, "selected-objects-by-pack"),
		neededPacks:           filepath.Join(directory, "needed-packs"),
	}
	regular, err := createRestoreOutput(selection.regularIndex)
	if err != nil {
		return selection, false, err
	}
	symlinks, err := createRestoreOutput(selection.symlinkIndex)
	if err != nil {
		regular.Abort()
		return selection, false, err
	}
	hashes, err := createRestoreOutput(selection.selectedHashesRaw)
	if err != nil {
		regular.Abort()
		symlinks.Abort()
		return selection, false, err
	}
	closed := false
	defer func() {
		if !closed {
			regular.Abort()
			symlinks.Abort()
			hashes.Abort()
		}
	}()
	err = snapshot.WalkIndex(format.DefaultLimits(), func(entry format.IndexEntry) error {
		if !expression.MatchString(entry.Path) {
			return nil
		}
		row, err := format.MarshalIndexEntry(entry)
		if err != nil {
			return err
		}
		if entry.Kind == format.KindFile {
			if err := regular.Write(row); err != nil {
				return err
			}
			hash := strings.TrimPrefix(entry.Ref, "blake2b:")
			if err := hashes.Printf("%s\t%d\n", hash, entry.Size); err != nil {
				return err
			}
			selection.regularCount++
		} else if err := symlinks.Write(row); err != nil {
			return err
		}
		status, err := destinationStatus(targetFD, entry, overwrite)
		if err != nil {
			return err
		}
		conflicts = conflicts || status == "conflict"
		if result.Planned == ^uint64(0) {
			return fmt.Errorf("restore plan count overflows")
		}
		result.Planned++
		if report != nil {
			return report(RestoreEvent{Kind: RestorePlanned, Path: entry.Path, FilesystemKind: entry.Kind, Status: status})
		}
		return nil
	})
	if err != nil {
		return selection, conflicts, err
	}
	if err := errors.Join(regular.Close(), symlinks.Close(), hashes.Close()); err != nil {
		return selection, conflicts, err
	}
	closed = true
	return selection, conflicts, nil
}

func prepareRestoreCatalogs(snapshot repository.State, selection restoreSelection) error {
	firstField := func(record []byte) ([]byte, error) {
		field, _, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(field) == 0 {
			return nil, fmt.Errorf("derived restore record lacks a key")
		}
		return field, nil
	}
	sortedHashes := filepath.Join(selection.directory, "selected-hashes.sorted")
	if err := extsort.SortFiles(selection.directory, []string{selection.selectedHashesRaw}, sortedHashes, extsort.Options{Key: firstField, MaxLineBytes: restoreDerivedLineBytes}); err != nil {
		return err
	}
	if err := compactSelectedHashes(sortedHashes, selection.selectedHashes); err != nil {
		return err
	}
	selected, err := openRestoreRows(selection.selectedHashes, 2)
	if err != nil {
		return err
	}
	defer selected.Close()
	selectedNext := selected.Next()
	allRaw, err := createRestoreOutput(filepath.Join(selection.directory, "all-objects-by-pack.raw"))
	if err != nil {
		return err
	}
	selectedRaw, err := createRestoreOutput(filepath.Join(selection.directory, "selected-objects-by-pack.raw"))
	if err != nil {
		allRaw.Abort()
		return err
	}
	outputsClosed := false
	defer func() {
		if !outputsClosed {
			allRaw.Abort()
			selectedRaw.Abort()
		}
	}()
	if err := snapshot.WalkObjects(format.DefaultLimits(), func(object format.ObjectEntry) error {
		if err := allRaw.Printf("%s\t%s\t%d\n", object.PackHash, object.PlaintextHash, object.PlaintextSize); err != nil {
			return err
		}
		for selectedNext && selected.Fields()[0] < object.PlaintextHash {
			return fmt.Errorf("selected plaintext %s has no object row", selected.Fields()[0])
		}
		if selectedNext && selected.Fields()[0] == object.PlaintextHash {
			size, err := strconv.ParseUint(selected.Fields()[1], 10, 64)
			if err != nil || size != object.PlaintextSize {
				return fmt.Errorf("selected plaintext %s size disagrees with object row", object.PlaintextHash)
			}
			if err := selectedRaw.Printf("%s\t%s\t%d\n", object.PackHash, object.PlaintextHash, object.PlaintextSize); err != nil {
				return err
			}
			selectedNext = selected.Next()
		}
		return nil
	}); err != nil {
		return err
	}
	if err := selected.Err(); err != nil {
		return err
	}
	if selectedNext {
		return fmt.Errorf("selected plaintext %s has no object row", selected.Fields()[0])
	}
	if err := errors.Join(allRaw.Close(), selectedRaw.Close()); err != nil {
		return err
	}
	outputsClosed = true
	if err := extsort.SortFiles(selection.directory, []string{filepath.Join(selection.directory, "all-objects-by-pack.raw")}, selection.allObjectsByPack, extsort.Options{Key: firstField, MaxLineBytes: restoreDerivedLineBytes}); err != nil {
		return err
	}
	if err := extsort.SortFiles(selection.directory, []string{filepath.Join(selection.directory, "selected-objects-by-pack.raw")}, selection.selectedObjectsByPack, extsort.Options{Key: firstField, MaxLineBytes: restoreDerivedLineBytes}); err != nil {
		return err
	}
	return writeNeededPacks(selection.selectedObjectsByPack, selection.neededPacks)
}

func compactSelectedHashes(input, output string) error {
	rows, err := openRestoreRows(input, 2)
	if err != nil {
		return err
	}
	defer rows.Close()
	destination, err := createRestoreOutput(output)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			destination.Abort()
		}
	}()
	var previousHash, previousSize string
	for rows.Next() {
		hash, size := rows.Fields()[0], rows.Fields()[1]
		if hash == previousHash {
			if size != previousSize {
				return fmt.Errorf("selected paths disagree on plaintext size for %s", hash)
			}
			continue
		}
		if err := destination.Printf("%s\t%s\n", hash, size); err != nil {
			return err
		}
		previousHash, previousSize = hash, size
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func writeNeededPacks(input, output string) error {
	rows, err := openRestoreRows(input, 3)
	if err != nil {
		return err
	}
	defer rows.Close()
	destination, err := createRestoreOutput(output)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			destination.Abort()
		}
	}()
	var previous string
	for rows.Next() {
		packHash := rows.Fields()[0]
		if packHash == previous {
			continue
		}
		if err := destination.Printf("%s\n", packHash); err != nil {
			return err
		}
		previous = packHash
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

type restoreRows struct {
	file       *os.File
	scanner    *bufio.Scanner
	fieldCount int
	fields     []string
	err        error
}

func openRestoreRows(path string, fieldCount int) (*restoreRows, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("derived restore file %q is not regular", path)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, restoreDerivedLineBytes), restoreDerivedLineBytes+1)
	return &restoreRows{file: file, scanner: scanner, fieldCount: fieldCount}, nil
}

func (rows *restoreRows) Next() bool {
	if rows == nil || rows.err != nil || !rows.scanner.Scan() {
		rows.fields = nil
		return false
	}
	rows.fields = strings.Split(rows.scanner.Text(), "\t")
	if len(rows.fields) != rows.fieldCount {
		rows.err = fmt.Errorf("derived restore record has %d fields, expected %d", len(rows.fields), rows.fieldCount)
		rows.fields = nil
		return false
	}
	return true
}

func (rows *restoreRows) Fields() []string { return rows.fields }
func (rows *restoreRows) Err() error {
	if rows.err != nil {
		return rows.err
	}
	return rows.scanner.Err()
}
func (rows *restoreRows) Close() error { return rows.file.Close() }

type restorePackStager struct {
	ctx       context.Context
	run       *runtime
	catalog   repository.State
	secretKey []byte
	selection restoreSelection
	all       *restoreRows
	selected  *restoreRows
	needed    *restoreRows
	allNext   bool
	selNext   bool
	needNext  bool

	current        string
	ciphertextPath string
	ciphertext     *os.File
	ciphertextSize uint64
	expected       map[string]uint64
	wanted         map[string]uint64
}

func stageSelectedContentStream(ctx context.Context, run *runtime, catalog repository.State, secretKey []byte, selection restoreSelection) (returnErr error) {
	all, err := openRestoreRows(selection.allObjectsByPack, 3)
	if err != nil {
		return err
	}
	selected, err := openRestoreRows(selection.selectedObjectsByPack, 3)
	if err != nil {
		all.Close()
		return err
	}
	needed, err := openRestoreRows(selection.neededPacks, 1)
	if err != nil {
		all.Close()
		selected.Close()
		return err
	}
	stager := &restorePackStager{
		ctx: ctx, run: run, catalog: catalog, secretKey: secretKey, selection: selection,
		all: all, selected: selected, needed: needed,
	}
	defer func() {
		stager.abort()
		returnErr = errors.Join(returnErr, all.Close(), selected.Close(), needed.Close())
	}()
	stager.allNext, stager.selNext, stager.needNext = all.Next(), selected.Next(), needed.Next()
	if err := catalog.WalkPacks(format.DefaultLimits(), stager.visitPart); err != nil {
		return err
	}
	if stager.current != "" {
		return fmt.Errorf("catalog ended inside selected pack %s", stager.current)
	}
	if stager.needNext {
		return fmt.Errorf("catalog has no parts for selected pack %s", stager.needed.Fields()[0])
	}
	if err := errors.Join(all.Err(), selected.Err(), needed.Err()); err != nil {
		return err
	}
	return nil
}

func (stager *restorePackStager) visitPart(part format.PackEntry) error {
	if err := stager.ctx.Err(); err != nil {
		return err
	}
	if !stager.needNext {
		return nil
	}
	neededHash := stager.needed.Fields()[0]
	if part.PackHash < neededHash {
		return nil
	}
	if part.PackHash > neededHash {
		return fmt.Errorf("catalog has no parts for selected pack %s", neededHash)
	}
	if stager.current == "" {
		if err := stager.startPack(part.PackHash); err != nil {
			return err
		}
	}
	if stager.current != part.PackHash {
		return fmt.Errorf("selected pack parts are not contiguous")
	}
	if ^uint64(0)-stager.ciphertextSize < part.PartSize || part.PartSize > ^uint64(0)/2 {
		return fmt.Errorf("pack staging size overflows")
	}
	if err := requireWorkspaceCapacity(stager.selection.directory, part.PartSize*2, 1, stager.run.options.SpaceReserveBytes); err != nil {
		return fmt.Errorf("stage pack %s part %d: %w", part.PackHash, part.PartNumber, err)
	}
	if err := fetchPackPart(stager.ctx, stager.run, part, stager.ciphertext, stager.selection.directory); err != nil {
		return err
	}
	stager.ciphertextSize += part.PartSize
	if part.PartNumber+1 == part.PartCount {
		if err := stager.finishPack(); err != nil {
			return fmt.Errorf("verify pack %s: %w", part.PackHash, err)
		}
		stager.needNext = stager.needed.Next()
	}
	return nil
}

func (stager *restorePackStager) startPack(packHash string) error {
	expected, next, err := loadRestorePackMembers(stager.all, stager.allNext, packHash)
	if err != nil {
		return err
	}
	stager.allNext = next
	wanted, next, err := loadRestorePackMembers(stager.selected, stager.selNext, packHash)
	if err != nil {
		return err
	}
	stager.selNext = next
	for hash, size := range wanted {
		expectedSize, present := expected[hash]
		if !present || expectedSize != size {
			return fmt.Errorf("selected plaintext %s disagrees with its pack member catalog", hash)
		}
	}
	path := filepath.Join(stager.selection.directory, "ciphertext-"+packHash)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	stager.current, stager.ciphertextPath, stager.ciphertext = packHash, path, file
	stager.ciphertextSize, stager.expected, stager.wanted = 0, expected, wanted
	return nil
}

func loadRestorePackMembers(rows *restoreRows, next bool, packHash string) (map[string]uint64, bool, error) {
	for next && rows.Fields()[0] < packHash {
		next = rows.Next()
	}
	if !next || rows.Fields()[0] != packHash {
		return nil, next, fmt.Errorf("object catalog has no members for selected pack %s", packHash)
	}
	members := make(map[string]uint64)
	for next && rows.Fields()[0] == packHash {
		if len(members) >= pack.MaximumMembersPerPack {
			return nil, next, fmt.Errorf("pack %s exceeds %d catalog members", packHash, pack.MaximumMembersPerPack)
		}
		hash := rows.Fields()[1]
		size, err := strconv.ParseUint(rows.Fields()[2], 10, 64)
		if err != nil {
			return nil, next, fmt.Errorf("invalid derived object size: %w", err)
		}
		if _, duplicate := members[hash]; duplicate {
			return nil, next, fmt.Errorf("pack %s contains duplicate object catalog rows", packHash)
		}
		members[hash] = size
		next = rows.Next()
	}
	if err := rows.Err(); err != nil {
		return nil, next, err
	}
	return members, next, nil
}

func (stager *restorePackStager) finishPack() error {
	if stager.ciphertext == nil || stager.current == "" {
		return fmt.Errorf("selected pack staging is not active")
	}
	if err := stager.ciphertext.Sync(); err != nil {
		return err
	}
	if err := stager.ciphertext.Close(); err != nil {
		return err
	}
	stager.ciphertext = nil
	fd, err := unix.Open(stager.ciphertextPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	ciphertext := os.NewFile(uintptr(fd), stager.ciphertextPath)
	consume := func(hash string, size uint64, reader io.Reader) error {
		expectedSize, wanted := stager.wanted[hash]
		if !wanted {
			_, err := io.Copy(io.Discard, reader)
			return err
		}
		if expectedSize != size {
			return fmt.Errorf("selected plaintext %s size changed", hash)
		}
		if err := requireWorkspaceCapacity(stager.selection.directory, size, 1, stager.run.options.SpaceReserveBytes); err != nil {
			return fmt.Errorf("stage selected plaintext %s: %w", hash, err)
		}
		plainPath := filepath.Join(stager.selection.directory, "plain-"+hash)
		file, err := os.OpenFile(plainPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(file, reader)
		if copyErr == nil && uint64(written) != size {
			copyErr = fmt.Errorf("plaintext size mismatch")
		}
		if copyErr == nil {
			copyErr = file.Sync()
		}
		if closeErr := file.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			_ = os.Remove(plainPath)
		}
		return copyErr
	}
	decryptErr := pack.DecryptAndRead(ciphertext, stager.current, stager.ciphertextSize, stager.secretKey, stager.expected, consume)
	closeErr := ciphertext.Close()
	removeErr := os.Remove(stager.ciphertextPath)
	if decryptErr == nil {
		decryptErr = closeErr
	}
	if decryptErr == nil {
		decryptErr = removeErr
	}
	stager.current, stager.ciphertextPath = "", ""
	stager.ciphertextSize, stager.expected, stager.wanted = 0, nil, nil
	return decryptErr
}

func (stager *restorePackStager) abort() {
	if stager.ciphertext != nil {
		_ = stager.ciphertext.Close()
		stager.ciphertext = nil
	}
	if stager.ciphertextPath != "" {
		_ = os.Remove(stager.ciphertextPath)
		stager.ciphertextPath = ""
	}
}

func fetchPackPart(ctx context.Context, run *runtime, part format.PackEntry, output *os.File, stage string) error {
	key, err := format.ObjectKey(part.PartHash, part.ObjectID)
	if err != nil {
		return err
	}
	expected := objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5}
	partFile, err := os.CreateTemp(stage, ".download-part-*")
	if err != nil {
		return err
	}
	partPath := partFile.Name()
	defer os.Remove(partPath)
	if err := partFile.Chmod(0o600); err != nil {
		partFile.Close()
		return err
	}
	fetched := false
	var failures []string
	for _, mirror := range run.config.Mirrors {
		if err := partFile.Truncate(0); err != nil {
			partFile.Close()
			return err
		}
		if _, err := partFile.Seek(0, io.SeekStart); err != nil {
			partFile.Close()
			return err
		}
		reader, err := run.reader(ctx, mirror)
		if err == nil {
			err = reader.GetVerified(ctx, key, expected, partFile)
		}
		if err == nil {
			fetched = true
			break
		}
		failures = append(failures, mirror.Canonical.Name+": "+errorText(err))
	}
	if !fetched {
		partFile.Close()
		return &packPartUnavailableError{packHash: part.PackHash, partNumber: part.PartNumber, failures: failures}
	}
	if err := partFile.Sync(); err != nil {
		partFile.Close()
		return err
	}
	if _, err := partFile.Seek(0, io.SeekStart); err != nil {
		partFile.Close()
		return err
	}
	written, copyErr := io.Copy(output, partFile)
	closeErr := partFile.Close()
	if copyErr != nil {
		return fmt.Errorf("stage downloaded part %d: %w", part.PartNumber, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("stage downloaded part %d: %w", part.PartNumber, closeErr)
	}
	if uint64(written) != part.PartSize {
		return fmt.Errorf("stage downloaded part %d: size mismatch", part.PartNumber)
	}
	return nil
}

func verifyAllStagedStream(selection restoreSelection) error {
	rows, err := openRestoreRows(selection.selectedHashes, 2)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		hash := rows.Fields()[0]
		expectedSize, err := strconv.ParseUint(rows.Fields()[1], 10, 64)
		if err != nil {
			return err
		}
		path := filepath.Join(selection.directory, "plain-"+hash)
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return fmt.Errorf("selected plaintext %s was not staged: %w", hash, err)
		}
		file := os.NewFile(uintptr(fd), path)
		digest, _ := blake2b.New512(nil)
		count, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(digest.Sum(nil)) != hash || uint64(count) != expectedSize {
			return fmt.Errorf("staged plaintext %s changed before publication", hash)
		}
	}
	return rows.Err()
}

func walkSelectedIndex(path string, visit func(format.IndexEntry) error) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	return format.WalkIndex(file, format.DefaultLimits(), visit)
}

func publishRestoreSelection(targetFD int, targetPath string, selection restoreSelection, overwrite bool, report func(RestoreEvent) error, result *RestoreResult) error {
	publicationFailed := false
	var publishFailure, reportFailure error
	reportEvent := func(event RestoreEvent) {
		if report == nil || reportFailure != nil {
			return
		}
		if err := report(event); err != nil {
			reportFailure = err
		}
	}
	publishFile := func(entry format.IndexEntry) error {
		if publicationFailed || reportFailure != nil {
			result.Remaining++
			reportEvent(RestoreEvent{Kind: RestoreRemaining, Path: entry.Path})
			return nil
		}
		var err error
		if entry.Kind == format.KindFile {
			hash := strings.TrimPrefix(entry.Ref, "blake2b:")
			err = publishRegular(targetFD, filepath.Join(selection.directory, "plain-"+hash), entry, overwrite)
		} else {
			err = publishSymlink(targetFD, entry, overwrite)
		}
		if err != nil {
			publicationFailed = true
			publishFailure = fmt.Errorf("publish restore path %q beneath %q: %w", terminalEscape(entry.Path), terminalEscape(targetPath), err)
			var published *publicationError
			if !errors.As(err, &published) || !published.Published() {
				result.Remaining++
				reportEvent(RestoreEvent{Kind: RestoreRemaining, Path: entry.Path})
				return nil
			}
		}
		result.Published++
		reportEvent(RestoreEvent{Kind: RestorePublished, Path: entry.Path})
		return nil
	}
	if err := walkSelectedIndex(selection.regularIndex, publishFile); err != nil {
		return err
	}
	if err := walkSelectedIndex(selection.symlinkIndex, publishFile); err != nil {
		return err
	}
	if reportFailure != nil {
		return reportFailure
	}
	return publishFailure
}
