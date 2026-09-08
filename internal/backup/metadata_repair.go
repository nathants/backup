package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"backup/internal/format"
	"backup/internal/metadatachain"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

func RepairMetadataEdge(ctx context.Context, options Options, destinationMirror, revision string) (MetadataRepairResult, error) {
	result := MetadataRepairResult{}
	run, err := openRuntime(options, true)
	if err != nil {
		return result, err
	}
	defer run.close()
	if txn, err := run.loadTransaction(); err != nil {
		return result, err
	} else if txn != nil {
		return result, fmt.Errorf("finish or reset the staged transaction before metadata repair")
	}
	head, history, err := run.validatedHead(true)
	if err != nil {
		return result, err
	}
	defer history.Close()
	if err := run.requirePinnedMirrors(head.State); err != nil {
		return result, err
	}
	selected, err := resolveHistoryRevision(run.repo, history, revision)
	if err != nil {
		return result, err
	}
	selectedIndex, found, err := history.IndexOf(selected.CommitID)
	if err != nil {
		return result, err
	}
	if !found {
		return result, fmt.Errorf("selected metadata revision is outside validated history")
	}
	mirror, ok := run.mirror(destinationMirror)
	if !ok {
		return result, fmt.Errorf("unknown destination mirror %q", destinationMirror)
	}
	writer, err := run.writer(ctx, mirror)
	if err != nil {
		return result, err
	}
	reader, err := run.reader(ctx, mirror)
	if err != nil {
		return result, err
	}
	secretKey, err := run.secretKey()
	if err != nil {
		return result, err
	}
	stage, err := os.MkdirTemp(run.options.statePath(), ".backup-metadata-repair-*")
	if err != nil {
		return result, err
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = removeTreeNoFollow(stage)
		return result, err
	}
	defer func() { _ = removeTreeNoFollow(stage) }()

	base := ""
	if selectedIndex > 0 {
		base, err = history.CommitID(selectedIndex - 1)
		if err != nil {
			return result, err
		}
	}
	buildDirectory := filepath.Join(stage, "build")
	if err := ensurePrivateDirectory(buildDirectory); err != nil {
		return result, err
	}
	partSize, ciphertextBudget, err := boundedMetadataStaging(buildDirectory, run.options.MetadataPartSize, run.options.SpaceReserveBytes)
	if err != nil {
		return result, err
	}
	built, err := metadatachain.Build(run.repo, selected.State.Format.RepositoryUUID, base, selected.CommitID, uint64(selectedIndex), selected.State.PublicKeys, buildDirectory, partSize, ciphertextBudget)
	if err != nil {
		return result, err
	}
	if err := validateRebuiltMetadataEdge(run.repo, built, selected.State.Format.RepositoryUUID, base, selected.CommitID, secretKey, stage, run.options.SpaceReserveBytes); err != nil {
		return result, fmt.Errorf("validate rebuilt metadata edge: %w", err)
	}
	for _, part := range built.Parts {
		key, err := format.MetadataPartKey(part.Manifest)
		if err != nil {
			return result, err
		}
		expected := objectstore.Object{Size: part.Manifest.Size, BLAKE2b: part.Manifest.Hash, SHA256: part.Manifest.SHA256, MD5: part.Manifest.MD5}
		create := writer.PutFile(ctx, key, part.Path, expected)
		if create.Disposition != objectstore.CreateAcknowledged && !((create.Disposition == objectstore.CreateConflict || create.Disposition == objectstore.CreateAmbiguous) && reader.Audit(ctx, key, expected) == nil) {
			return result, fmt.Errorf("destination did not acknowledge rebuilt metadata part %s: %s", key, errorText(create.Err))
		}
	}
	manifestData, err := os.ReadFile(built.ManifestPath)
	if err != nil {
		return result, err
	}
	manifestKey, err := format.MetadataManifestKey(built.Manifest.TipCommit, built.ManifestHash, built.ManifestObjectID)
	if err != nil {
		return result, err
	}
	manifestExpected := objectstore.HashBytes(manifestData)
	if manifestExpected.BLAKE2b != built.ManifestHash {
		return result, fmt.Errorf("rebuilt metadata manifest identity changed")
	}
	create := writer.PutFile(ctx, manifestKey, built.ManifestPath, manifestExpected)
	if create.Disposition != objectstore.CreateAcknowledged && !((create.Disposition == objectstore.CreateConflict || create.Disposition == objectstore.CreateAmbiguous) && reader.Audit(ctx, manifestKey, manifestExpected) == nil) {
		return result, fmt.Errorf("destination did not acknowledge rebuilt metadata manifest %s: %s", manifestKey, errorText(create.Err))
	}
	result.TipCommit = selected.CommitID
	result.ManifestHash = built.ManifestHash
	result.ManifestObjectID = built.ManifestObjectID
	result.Parts = len(built.Parts)
	return result, nil
}

type serialFileReader struct {
	paths   []string
	next    int
	current io.ReadCloser
	open    func(string) (io.ReadCloser, error)
	closed  bool
}

func (reader *serialFileReader) Read(buffer []byte) (int, error) {
	for {
		if reader.closed {
			return 0, io.EOF
		}
		if reader.current == nil {
			if reader.next == len(reader.paths) {
				return 0, io.EOF
			}
			if reader.open == nil {
				return 0, fmt.Errorf("serial file reader has no opener")
			}
			current, err := reader.open(reader.paths[reader.next])
			if err != nil {
				return 0, err
			}
			reader.current = current
			reader.next++
		}
		count, err := reader.current.Read(buffer)
		if !errors.Is(err, io.EOF) {
			return count, err
		}
		closeErr := reader.current.Close()
		reader.current = nil
		if closeErr != nil {
			return count, closeErr
		}
		if count != 0 {
			return count, nil
		}
	}
}

func (reader *serialFileReader) Close() error {
	reader.closed = true
	if reader.current == nil {
		return nil
	}
	err := reader.current.Close()
	reader.current = nil
	return err
}

func validateRebuiltMetadataEdge(source *repository.Managed, built metadatachain.Result, repositoryUUID, base, tip string, secretKey []byte, stage string, reserveBytes uint64) error {
	if built.Manifest.BundleSize > ^uint64(0)/2 {
		return fmt.Errorf("metadata-repair workspace requirement overflows")
	}
	// The encrypted parts already occupy their build directory. Validation
	// additionally retains the decrypted bundle plus a Git quarantine whose
	// packed representation is conservatively bounded by another bundle size.
	if err := requireWorkspaceCapacity(stage, built.Manifest.BundleSize*2, uint64(len(built.Parts))+32, reserveBytes); err != nil {
		return fmt.Errorf("metadata-repair validation workspace: %w", err)
	}
	input := &serialFileReader{paths: make([]string, len(built.Parts)), open: func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}}
	for index, part := range built.Parts {
		input.paths[index] = part.Path
	}
	bundlePath := filepath.Join(stage, "rebuilt.bundle")
	decryptErr := decryptMetadataBundleReader(input, bundlePath, built.Manifest, secretKey)
	closeErr := input.Close()
	if decryptErr != nil || closeErr != nil {
		return errors.Join(decryptErr, closeErr)
	}
	quarantine, err := initializeMetadataQuarantine(filepath.Join(stage, "quarantine.git"))
	if err != nil {
		return err
	}
	priorTip := strings.Repeat("0", 64)
	if base != "" {
		if _, err := quarantine.RunGit(nil, 64<<10, "fetch", source.Directory, base+":refs/backup/recovered-tip"); err != nil {
			return fmt.Errorf("seed quarantine base: %w", err)
		}
		priorTip = base
	}
	if err := applyMetadataBundle(quarantine, bundlePath, built.Manifest, priorTip); err != nil {
		return err
	}
	history, err := (repository.Validator{Repo: quarantine.Directory, Limits: format.DefaultLimits()}).ValidateHistory("refs/backup/recovered-tip")
	if err != nil {
		return err
	}
	defer history.Close()
	validatedTip, err := history.Tip()
	if err != nil {
		return err
	}
	genesisFormat, err := history.GenesisFormat()
	if err != nil {
		return err
	}
	if validatedTip.CommitID != tip || genesisFormat.RepositoryUUID != repositoryUUID || built.Manifest.Sequence != uint64(history.Len()-1) {
		return fmt.Errorf("rebuilt representation reconstructed the wrong repository, sequence, or tip")
	}
	return nil
}
