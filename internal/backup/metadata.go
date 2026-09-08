package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"backup/internal/format"
	"backup/internal/metadatachain"
	"backup/internal/objectstore"
	"backup/internal/repository"

	"github.com/nathants/go-libsodium"
)

type manifestRepresentation struct {
	Key      string
	Hash     string
	ObjectID string
	Manifest format.MetadataManifest
	Data     []byte
}

func listManifestRepresentations(ctx context.Context, client *objectstore.Client, tip, repositoryUUID string) ([]manifestRepresentation, error) {
	if !isCommitID(tip) {
		return nil, fmt.Errorf("invalid metadata tip")
	}
	prefix := "metadata/manifests/" + tip + "/"
	keys, err := client.ListLimited(ctx, prefix, maximumRecoveryManifestKeys)
	if err != nil {
		return nil, err
	}
	var representations []manifestRepresentation
	unknown := false
	corrupt := false
	totalManifestBytes := 0
	var failures []string
	failureCount := 0
	recordFailure := func(err error) {
		failureCount++
		if len(failures) < maximumRecoveryFailureDetails {
			failures = append(failures, terminalEscape(err.Error()))
		}
	}
	for _, key := range keys {
		hash, objectID, err := parseManifestKey(key, tip)
		if err != nil {
			recordFailure(err)
			continue
		}
		data, err := client.GetManifest(ctx, key, hash)
		if err != nil {
			unknown = unknown || !conclusiveObjectFailure(err)
			corrupt = corrupt || errors.Is(err, objectstore.ErrCorrupt)
			recordFailure(err)
			continue
		}
		if len(data) > maximumRecoveryManifestBytes-totalManifestBytes {
			return nil, fmt.Errorf("metadata manifests for tip %s exceed %d bytes", tip, maximumRecoveryManifestBytes)
		}
		totalManifestBytes += len(data)
		manifest, err := format.ParseMetadataManifest(bytes.NewReader(data), manifestLimits())
		if err != nil || manifest.RepositoryUUID != repositoryUUID || manifest.TipCommit != tip {
			if err == nil {
				err = fmt.Errorf("manifest identity disagrees with the selected repository and tip")
			}
			recordFailure(err)
			continue
		}
		representations = append(representations, manifestRepresentation{Key: key, Hash: hash, ObjectID: objectID, Manifest: manifest, Data: data})
	}
	sort.Slice(representations, func(left, right int) bool { return representations[left].Key < representations[right].Key })
	if unknown || len(representations) == 0 && failureCount != 0 {
		detail := strings.Join(failures, "; ")
		if failureCount > len(failures) {
			detail += fmt.Sprintf("; %d additional failures omitted", failureCount-len(failures))
		}
		err := fmt.Errorf("metadata manifest inspection for tip %s (%s)", tip, detail)
		if len(representations) == 0 && corrupt {
			err = fmt.Errorf("%w: %w", objectstore.ErrCorrupt, err)
		} else if !unknown {
			err = fmt.Errorf("%w: %w", objectstore.ErrMissing, err)
		}
		// Retain usable alternatives even if another representation is unavailable.
		return representations, err
	}
	return representations, nil
}

func parseManifestKey(key, tip string) (string, string, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 5 || parts[0] != "metadata" || parts[1] != "manifests" || parts[2] != tip {
		return "", "", fmt.Errorf("unexpected metadata-manifest key %q", key)
	}
	if _, err := format.MetadataManifestKey(tip, parts[3], parts[4]); err != nil {
		return "", "", err
	}
	return parts[3], parts[4], nil
}

func manifestLimits() format.Limits {
	limits := format.DefaultLimits()
	limits.MaxFileBytes = format.MaximumMetadataManifestBytes
	limits.MaxLineBytes = 16 << 10
	limits.MaxFieldBytes = 8 << 10
	limits.MaxRecords = 9 + format.MaximumMetadataManifestParts
	return limits
}

func auditManifestChain(ctx context.Context, client *objectstore.Client, history *repository.History, targetIndex int, repositoryUUID string, visit func(index int, representation manifestRepresentation) error) error {
	if history == nil || targetIndex < 0 || targetIndex >= history.Len() {
		return fmt.Errorf("invalid target history position")
	}
	for index := 0; index <= targetIndex; index++ {
		tip, err := history.CommitID(index)
		if err != nil {
			return err
		}
		base := "-"
		kind := format.BundleFull
		if index > 0 {
			base, err = history.CommitID(index - 1)
			if err != nil {
				return err
			}
			kind = format.BundleIncremental
		}
		representations, listErr := listManifestRepresentations(ctx, client, tip, repositoryUUID)
		if listErr != nil && len(representations) == 0 {
			return listErr
		}
		unknown := listErr != nil
		corrupt := false
		var failures []string
		accepted := false
		for _, representation := range representations {
			manifest := representation.Manifest
			if manifest.Sequence != uint64(index) || manifest.TipCommit != tip || manifest.Kind != kind || manifest.BaseCommit != base {
				continue
			}
			valid := true
			for _, part := range manifest.Parts {
				key, err := format.MetadataPartKey(part)
				if err != nil {
					return err
				}
				expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
				if err := client.Audit(ctx, key, expected); err != nil {
					unknown = unknown || !conclusiveObjectFailure(err)
					corrupt = corrupt || errors.Is(err, objectstore.ErrCorrupt)
					failures = appendRecoveryFailure(failures, fmt.Sprintf("%s: %v", key, err))
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			if visit != nil {
				if err := visit(index, representation); err != nil {
					return err
				}
			}
			accepted = true
			break
		}
		if !accepted {
			err := fmt.Errorf("no complete metadata representation for sequence %d tip %s (%s)", index, tip, strings.Join(failures, "; "))
			if corrupt {
				return fmt.Errorf("%w: %w", objectstore.ErrCorrupt, err)
			}
			if !unknown {
				return fmt.Errorf("%w: %w", objectstore.ErrMissing, err)
			}
			return errors.Join(err, listErr)
		}
	}
	return nil
}

func fetchMetadataBundle(ctx context.Context, client *objectstore.Client, representation manifestRepresentation, destination, stage string) error {
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(destination)
		}
	}()
	for _, part := range representation.Manifest.Parts {
		key, err := format.MetadataPartKey(part)
		if err != nil {
			return err
		}
		expected := objectstore.Object{Size: part.Size, BLAKE2b: part.Hash, SHA256: part.SHA256, MD5: part.MD5}
		temporary, err := os.CreateTemp(stage, ".metadata-download-*")
		if err != nil {
			return err
		}
		temporaryPath := temporary.Name()
		if err := temporary.Chmod(0o600); err != nil {
			_ = temporary.Close()
			return err
		}
		if err := client.GetVerified(ctx, key, expected, temporary); err != nil {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
			return err
		}
		if err := temporary.Sync(); err != nil {
			_ = temporary.Close()
			return err
		}
		if _, err := temporary.Seek(0, io.SeekStart); err != nil {
			_ = temporary.Close()
			return err
		}
		written, err := io.Copy(output, temporary)
		closeErr := temporary.Close()
		_ = os.Remove(temporaryPath)
		if err != nil || closeErr != nil || uint64(written) != part.Size {
			if err == nil {
				err = closeErr
			}
			return fmt.Errorf("stage metadata part %d: %w", part.Number, err)
		}
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func decryptMetadataBundle(ciphertextPath, bundlePath string, manifest format.MetadataManifest, secretKey *libsodium.Keyring) error {
	input, err := os.Open(ciphertextPath)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	return decryptMetadataBundleReader(input, bundlePath, manifest, secretKey)
}

func decryptMetadataBundleReader(input io.Reader, bundlePath string, manifest format.MetadataManifest, secretKey *libsodium.Keyring) error {
	if input == nil {
		return fmt.Errorf("metadata ciphertext reader is required")
	}
	output, err := os.OpenFile(bundlePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(bundlePath)
		}
	}()
	if err := metadatachain.Decrypt(input, manifest.BundleHash, manifest.BundleSize, secretKey, output); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

const metadataCandidateRef = "refs/backup/recovery-candidate"

func initializeMetadataQuarantine(quarantine string) (*repository.Managed, error) {
	if err := repository.InitializeBareSHA256(quarantine); err != nil {
		return nil, fmt.Errorf("initialize quarantine repository: %w", err)
	}
	repo := &repository.Managed{Directory: quarantine}
	// Fetch must not leave detached writers repacking objects while validation
	// or failed-attempt cleanup inspects this private repository.
	if _, err := repo.RunGit(nil, 1024, "config", "maintenance.auto", "false"); err != nil {
		return nil, fmt.Errorf("disable quarantine automatic maintenance: %w", err)
	}
	return repo, nil
}

func applyMetadataBundle(repo *repository.Managed, bundlePath string, manifest format.MetadataManifest, priorTip string) error {
	file, err := os.Open(bundlePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	reader := bufio.NewReaderSize(file, 4096)
	if err := readMetadataBundleHeader(reader, manifest); err != nil {
		return err
	}
	_, _ = repo.RunGit(nil, 1024, "update-ref", "-d", metadataCandidateRef)
	if _, err := repo.RunGit(nil, 1024, "cat-file", "-e", manifest.TipCommit+"^{object}"); err == nil {
		return fmt.Errorf("bundle tip already existed before its declared edge")
	}
	if output, err := repo.RunGit(nil, 64<<10, "bundle", "verify", bundlePath); err != nil {
		return fmt.Errorf("verify bundle: %w: %s", err, output)
	}
	// Bundle fetch did not honor fetch.fsckObjects in Git 2.36. Use the native
	// strict indexer explicitly on the pack following the validated header,
	// rather than depending on newer bundle-transport configuration behavior.
	if err := repo.ImportPack(reader); err != nil {
		return fmt.Errorf("apply bundle with strict pack validation: %w", err)
	}
	if _, err := repo.RunGit(nil, 1024, "update-ref", metadataCandidateRef, manifest.TipCommit); err != nil {
		return fmt.Errorf("record imported bundle tip: %w", err)
	}
	resolved, err := repo.RunGit(nil, 1024, "rev-parse", "--verify", metadataCandidateRef)
	if err != nil || strings.TrimSpace(string(resolved)) != manifest.TipCommit {
		return fmt.Errorf("bundle reconstructed the wrong tip")
	}
	// Reject missing/wrong-type links and every extra object at this exact
	// edge. Deferring reachability until the last tip could let a later bundle
	// conceal objects injected early. New object bytes were checked on import;
	// a final full fsck rechecks all stored bytes before accepting the chain.
	if err := validateMetadataGraph(repo, manifest.TipCommit, true); err != nil {
		return err
	}
	if _, err := repo.RunGit(nil, 1024, "update-ref", "refs/backup/recovered-tip", manifest.TipCommit, priorTip); err != nil {
		return fmt.Errorf("advance recovered metadata tip: %w", err)
	}
	return nil
}

func validateMetadataGraph(repo *repository.Managed, tip string, connectivityOnly bool) error {
	arguments := []string{"fsck", "--strict", "--no-reflogs", "--unreachable", "--no-progress"}
	if connectivityOnly {
		arguments = append(arguments, "--connectivity-only")
	}
	arguments = append(arguments, tip)
	output, err := repo.RunGit(nil, 64<<10, arguments...)
	if err != nil {
		return fmt.Errorf("validate bundle object graph: %w", err)
	}
	if detail := strings.TrimSpace(string(output)); detail != "" {
		return fmt.Errorf("bundle contains objects outside its declared tip graph: %s", detail)
	}
	return nil
}

func readMetadataBundleHeader(reader *bufio.Reader, manifest format.MetadataManifest) error {
	readLine := func() (string, error) {
		line, readErr := reader.ReadSlice('\n')
		if readErr != nil {
			if readErr == bufio.ErrBufferFull {
				return "", fmt.Errorf("git bundle header line exceeds 4096 bytes")
			}
			return "", fmt.Errorf("read git bundle header: %w", readErr)
		}
		return string(line), nil
	}
	line, err := readLine()
	if err != nil || line != "# v3 git bundle\n" {
		return fmt.Errorf("git bundle must use exact version 3 framing")
	}
	line, err = readLine()
	if err != nil || line != "@object-format=sha256\n" {
		return fmt.Errorf("git bundle must declare only SHA-256 object format")
	}
	var prerequisites []string
	var advertised []string
	for {
		line, err = readLine()
		if err != nil {
			return err
		}
		if line == "\n" {
			break
		}
		if strings.HasPrefix(line, "@") {
			return fmt.Errorf("git bundle contains an unexpected capability")
		}
		trimmed := strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(trimmed, "-"):
			fields := strings.SplitN(strings.TrimPrefix(trimmed, "-"), " ", 2)
			if len(fields) != 2 || !isCommitID(fields[0]) || fields[1] == "" {
				return fmt.Errorf("git bundle contains a malformed prerequisite")
			}
			prerequisites = append(prerequisites, fields[0])
		default:
			fields := strings.Split(trimmed, " ")
			if len(fields) != 2 || !isCommitID(fields[0]) || fields[1] != "refs/backup/bundle-tip" {
				return fmt.Errorf("git bundle contains an unexpected advertised ref")
			}
			advertised = append(advertised, fields[0])
		}
		if len(prerequisites)+len(advertised) > 2 {
			return fmt.Errorf("git bundle header contains excessive records")
		}
	}
	if len(advertised) != 1 || advertised[0] != manifest.TipCommit {
		return fmt.Errorf("git bundle must advertise exactly its declared tip")
	}
	switch manifest.Kind {
	case format.BundleFull:
		if manifest.BaseCommit != "-" || len(prerequisites) != 0 {
			return fmt.Errorf("full git bundle must have no prerequisites")
		}
	case format.BundleIncremental:
		if !isCommitID(manifest.BaseCommit) || len(prerequisites) != 1 || prerequisites[0] != manifest.BaseCommit {
			return fmt.Errorf("incremental git bundle must require exactly its declared base")
		}
	default:
		return fmt.Errorf("git bundle manifest has an invalid kind")
	}
	return nil
}

func materializeMetadataChain(ctx context.Context, client *objectstore.Client, chain [][]manifestRepresentation, secretKey *libsodium.Keyring, quarantine, stage string) ([]manifestRepresentation, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("metadata chain is empty")
	}
	for edgeIndex, alternatives := range chain {
		if len(alternatives) == 0 {
			return nil, fmt.Errorf("metadata edge %d has no physical representations", edgeIndex)
		}
	}
	// Extend one private repository on the healthy path. Failed imports can
	// leave objects behind even without advancing a ref: discard the whole
	// attempt, remember the rejected representation, and replay from scratch.
	// Equivalent representations reconstruct the same commits, so changing an
	// earlier choice never makes a rejected later representation eligible again.
	choices := make([]int, len(chain))
	attemptRoot := ""
	defer func() {
		if attemptRoot != "" {
			_ = removeTreeNoFollow(attemptRoot)
		}
	}()
	var failures []string
	for attempt := 0; attempt < maximumRecoveryMaterializations; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var err error
		attemptRoot, err = os.MkdirTemp(stage, "quarantine-*")
		if err != nil {
			return nil, err
		}
		attemptRepository := filepath.Join(attemptRoot, "repository.git")
		repo, err := initializeMetadataQuarantine(attemptRepository)
		if err != nil {
			return nil, err
		}
		chosen := make([]manifestRepresentation, 0, len(chain))
		priorTip := strings.Repeat("0", 64)
		for edgeIndex, alternatives := range chain {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			representation := alternatives[choices[edgeIndex]]
			ciphertextPath := filepath.Join(attemptRoot, "metadata.ciphertext")
			bundlePath := filepath.Join(attemptRoot, "metadata.bundle")
			importErr := func() error {
				if err := fetchMetadataBundle(ctx, client, representation, ciphertextPath, attemptRoot); err != nil {
					return err
				}
				if err := decryptMetadataBundle(ciphertextPath, bundlePath, representation.Manifest, secretKey); err != nil {
					return err
				}
				return applyMetadataBundle(repo, bundlePath, representation.Manifest, priorTip)
			}()
			if importErr != nil {
				failures = appendRecoveryFailure(failures, fmt.Sprintf("edge %d %s: %v", edgeIndex, representation.Key, importErr))
				choices[edgeIndex]++
				if choices[edgeIndex] == len(alternatives) {
					return nil, fmt.Errorf("no usable physical representation for metadata edge %d (%s)", edgeIndex, strings.Join(failures, "; "))
				}
				break
			}
			if err := os.Remove(ciphertextPath); err != nil {
				return nil, err
			}
			if err := os.Remove(bundlePath); err != nil {
				return nil, err
			}
			chosen = append(chosen, representation)
			priorTip = representation.Manifest.TipCommit
		}
		if len(chosen) == len(chain) {
			if err := validateMetadataGraph(repo, priorTip, false); err != nil {
				return nil, err
			}
			if err := os.Rename(attemptRepository, quarantine); err != nil {
				return nil, fmt.Errorf("retain reconstructed metadata repository: %w", err)
			}
			if err := syncDirectory(filepath.Dir(quarantine)); err != nil {
				return nil, err
			}
			if err := removeTreeNoFollow(attemptRoot); err != nil {
				return nil, err
			}
			return chosen, nil
		}
		if err := removeTreeNoFollow(attemptRoot); err != nil {
			return nil, fmt.Errorf("discard failed metadata import: %w", err)
		}
		attemptRoot = ""
	}
	return nil, fmt.Errorf("metadata chain exceeds %d recovery attempts (%s)", maximumRecoveryMaterializations, strings.Join(failures, "; "))
}
