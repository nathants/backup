package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/repository"
)

const (
	maximumRecoveryManifestKeys     = 100_000
	maximumRecoveryManifestBytes    = 256 << 20
	maximumRecoveryLogicalPaths     = 10_000
	maximumRecoveryPathChoices      = 1_000_000
	maximumRecoveryMaterializations = 10_000
	maximumRecoveryCommitRecords    = 10_000_000
	maximumRecoveryFailureDetails   = 8
)

type recoveryCandidate struct {
	TipCommit      string
	RepositoryUUID string
	Sequence       uint64
	Representation manifestRepresentation
}

type recoveryLogicalEdge struct {
	RepositoryUUID string
	Sequence       uint64
	BaseCommit     string
	TipCommit      string
	Kind           string
	Alternatives   []manifestRepresentation
}

type recoveryPath struct {
	Edges [][]manifestRepresentation
}

func recoveryWorkspaceRequirement(path recoveryPath) (uint64, uint64, error) {
	var total, maximum, inodes uint64
	for _, alternatives := range path.Edges {
		var edgeBytes, edgeInodes uint64
		for _, representation := range alternatives {
			if representation.Manifest.BundleSize > edgeBytes {
				edgeBytes = representation.Manifest.BundleSize
			}
			candidateInodes := uint64(len(representation.Manifest.Parts)) + 4
			if candidateInodes > edgeInodes {
				edgeInodes = candidateInodes
			}
		}
		if edgeBytes == 0 || total > ^uint64(0)-edgeBytes || inodes > ^uint64(0)-edgeInodes {
			return 0, 0, fmt.Errorf("recovery workspace requirement overflows")
		}
		total += edgeBytes
		inodes += edgeInodes
		if edgeBytes > maximum {
			maximum = edgeBytes
		}
	}
	// Allow Git import/index workspace plus one ciphertext and plaintext
	// bundle. Encrypted sizes bound plaintext bundle bytes, not Git's possible
	// object expansion; enforced aggregate resource bounds remain operator-owned.
	if total > ^uint64(0)/2 || maximum > (^uint64(0)-total*2)/2 {
		return 0, 0, fmt.Errorf("recovery workspace requirement overflows")
	}
	return total*2 + maximum*2, inodes, nil
}

type verifiedRecovery struct {
	Tip            string
	RepositoryPath string
	CommitIDsPath  string
}

func Recover(ctx context.Context, options Options, request RecoverRequest) (RecoverResult, error) {
	result := RecoverResult{}
	normalized, err := options.normalized()
	if err != nil {
		return result, err
	}
	if request.Tip != "" && !isCommitID(request.Tip) {
		return result, fmt.Errorf("recovery tip must be an exact 64-hex commit ID")
	}
	config, err := localconfig.Load(normalized.ConfigPath)
	if err != nil {
		return result, err
	}
	run := &runtime{options: normalized, config: config}
	mirror, ok := run.mirror(request.Mirror)
	if !ok {
		return result, fmt.Errorf("unknown mirror %q", request.Mirror)
	}
	client, err := run.client(ctx, mirror)
	if err != nil {
		return result, err
	}
	candidates, err := discoverRecoveryCandidates(ctx, client, request.Tip)
	if err != nil {
		return result, err
	}
	if len(candidates) == 0 {
		return result, fmt.Errorf("mirror contains no valid metadata completion manifests")
	}
	secretKey, err := run.secretKey()
	if err != nil {
		return result, err
	}
	// Build retained candidates on the destination filesystem so publication
	// renames the exact verified repository, including when TMPDIR is elsewhere.
	// Listing needs no destination and retains only the verified commit IDs.
	destination, parent := "", ""
	if !request.ListOnly {
		if request.Destination == "" {
			return result, fmt.Errorf("recovery destination is required")
		}
		destination, err = filepath.Abs(request.Destination)
		if err != nil {
			return result, err
		}
		if _, err := os.Lstat(destination); err == nil {
			return result, fmt.Errorf("recovery destination already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		parent = filepath.Dir(destination)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return result, err
		}
	}
	verificationWorkspace, err := os.MkdirTemp(parent, ".backup-recover-*")
	if err != nil {
		return result, err
	}
	if err := os.Chmod(verificationWorkspace, 0o700); err != nil {
		_ = removeTreeNoFollow(verificationWorkspace)
		return result, err
	}
	defer func() { _ = removeTreeNoFollow(verificationWorkspace) }()
	verified, failures, err := verifyRecoveryCandidates(ctx, client, candidates, request.Tip, secretKey, verificationWorkspace, normalized.SpaceReserveBytes, !request.ListOnly)
	if err != nil {
		return result, err
	}
	result.Available, err = reportAvailableRecoveries(verified, verificationWorkspace, request.Report)
	if err != nil {
		return result, err
	}
	if request.ListOnly {
		if len(verified) == 0 {
			return result, fmt.Errorf("mirror contains no recoverable metadata history (%s)", summarizeRecoveryFailures(failures))
		}
		return result, nil
	}

	var selected verifiedRecovery
	if request.Tip != "" {
		if len(verified) == 0 {
			return result, fmt.Errorf("no verified metadata chain reconstructs tip %s (%s)", request.Tip, summarizeRecoveryFailures(failures))
		}
		selected = verified[0]
	} else {
		maximal, err := maximalVerifiedRecoveries(verified)
		if err != nil {
			return result, err
		}
		if len(maximal) == 0 {
			return result, fmt.Errorf("mirror contains no recoverable metadata history (%s)", summarizeRecoveryFailures(failures))
		}
		if len(maximal) != 1 {
			tips := make([]string, len(maximal))
			for index, candidate := range maximal {
				tips[index] = candidate.Tip
			}
			sort.Strings(tips)
			return result, fmt.Errorf("mirror has %d verified maximal tips (%s); select one with --tip", len(tips), strings.Join(tips, ", "))
		}
		selected = maximal[0]
	}
	if selected.RepositoryPath == "" {
		return result, fmt.Errorf("selected verified repository was not retained")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := os.Rename(selected.RepositoryPath, destination); err != nil {
		return result, err
	}
	if err := syncDirectory(parent); err != nil {
		return result, err
	}
	result.RecoveredTip, result.Destination = selected.Tip, destination
	return result, nil
}

func discoverRecoveryCandidates(ctx context.Context, client *objectstore.Client, exactTip string) ([]recoveryCandidate, error) {
	var candidates []recoveryCandidate
	totalKeys, totalBytes := 0, 0
	load := func(prefix, requiredTip string) ([]recoveryCandidate, error) {
		remaining := maximumRecoveryManifestKeys - totalKeys
		if remaining <= 0 {
			return nil, fmt.Errorf("recovery metadata listing exceeds %d keys", maximumRecoveryManifestKeys)
		}
		keys, err := client.ListLimited(ctx, prefix, remaining)
		if err != nil {
			return nil, err
		}
		totalKeys += len(keys)
		sort.Strings(keys)
		var loaded []recoveryCandidate
		for _, key := range keys {
			parts := strings.Split(key, "/")
			if len(parts) != 5 || parts[0] != "metadata" || parts[1] != "manifests" || requiredTip != "" && parts[2] != requiredTip {
				continue
			}
			tip, hash, objectID := parts[2], parts[3], parts[4]
			if _, err := format.MetadataManifestKey(tip, hash, objectID); err != nil {
				continue
			}
			data, err := client.GetManifest(ctx, key, hash)
			if err != nil {
				continue
			}
			if len(data) > maximumRecoveryManifestBytes-totalBytes {
				return nil, fmt.Errorf("recovery metadata manifests exceed %d bytes", maximumRecoveryManifestBytes)
			}
			totalBytes += len(data)
			manifest, err := format.ParseMetadataManifest(bytes.NewReader(data), manifestLimits())
			if err != nil || manifest.TipCommit != tip {
				continue
			}
			loaded = append(loaded, recoveryCandidate{
				TipCommit: tip, RepositoryUUID: manifest.RepositoryUUID, Sequence: manifest.Sequence,
				Representation: manifestRepresentation{Key: key, Hash: hash, ObjectID: objectID, Manifest: manifest, Data: data},
			})
		}
		return loaded, nil
	}
	if exactTip == "" {
		return load("metadata/manifests/", "")
	}
	pending := []string{exactTip}
	loadedTips := make(map[string]bool)
	for len(pending) != 0 {
		tip := pending[0]
		pending = pending[1:]
		if loadedTips[tip] {
			continue
		}
		loadedTips[tip] = true
		loaded, err := load("metadata/manifests/"+tip+"/", tip)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, loaded...)
		for _, candidate := range loaded {
			manifest := candidate.Representation.Manifest
			if manifest.Kind == format.BundleIncremental && !loadedTips[manifest.BaseCommit] {
				pending = append(pending, manifest.BaseCommit)
			}
		}
	}
	return candidates, nil
}

func recoveryLogicalPaths(candidates []recoveryCandidate, tip string) ([]recoveryPath, error) {
	type edgeIdentity struct {
		repositoryUUID string
		sequence       uint64
		baseCommit     string
		tipCommit      string
		kind           string
	}
	grouped := make(map[edgeIdentity]*recoveryLogicalEdge)
	for _, candidate := range candidates {
		manifest := candidate.Representation.Manifest
		identity := edgeIdentity{manifest.RepositoryUUID, manifest.Sequence, manifest.BaseCommit, manifest.TipCommit, manifest.Kind}
		edge := grouped[identity]
		if edge == nil {
			edge = &recoveryLogicalEdge{
				RepositoryUUID: manifest.RepositoryUUID, Sequence: manifest.Sequence,
				BaseCommit: manifest.BaseCommit, TipCommit: manifest.TipCommit, Kind: manifest.Kind,
			}
			grouped[identity] = edge
		}
		edge.Alternatives = append(edge.Alternatives, candidate.Representation)
	}
	byTip := make(map[string][]*recoveryLogicalEdge)
	for _, edge := range grouped {
		sort.Slice(edge.Alternatives, func(left, right int) bool { return edge.Alternatives[left].Key < edge.Alternatives[right].Key })
		byTip[edge.TipCommit] = append(byTip[edge.TipCommit], edge)
	}
	for candidateTip := range byTip {
		sort.Slice(byTip[candidateTip], func(left, right int) bool {
			return recoveryLogicalEdgeLess(byTip[candidateTip][left], byTip[candidateTip][right])
		})
	}

	var paths []recoveryPath
	var reversed []*recoveryLogicalEdge
	choices := 0
	var walk func(*recoveryLogicalEdge) error
	walk = func(edge *recoveryLogicalEdge) error {
		choices++
		if choices > maximumRecoveryPathChoices {
			return fmt.Errorf("recovery graph exceeds %d logical choices", maximumRecoveryPathChoices)
		}
		if len(reversed) >= len(candidates) {
			return fmt.Errorf("recovery graph path exceeds its manifest count")
		}
		reversed = append(reversed, edge)
		defer func() { reversed = reversed[:len(reversed)-1] }()
		if edge.Kind == format.BundleFull {
			edges := make([][]manifestRepresentation, len(reversed))
			for index := range reversed {
				edges[len(reversed)-1-index] = reversed[index].Alternatives
			}
			paths = append(paths, recoveryPath{Edges: edges})
			if len(paths) > maximumRecoveryLogicalPaths {
				return fmt.Errorf("recovery graph exceeds %d logical paths", maximumRecoveryLogicalPaths)
			}
			return nil
		}
		if edge.Kind != format.BundleIncremental || edge.Sequence == 0 {
			return nil
		}
		for _, parent := range byTip[edge.BaseCommit] {
			if parent.RepositoryUUID != edge.RepositoryUUID || parent.Sequence != edge.Sequence-1 {
				continue
			}
			if err := walk(parent); err != nil {
				return err
			}
		}
		return nil
	}
	for _, edge := range byTip[tip] {
		if err := walk(edge); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func recoveryLogicalEdgeLess(left, right *recoveryLogicalEdge) bool {
	leftKey := fmt.Sprintf("%s\x00%020d\x00%s\x00%s\x00%s", left.RepositoryUUID, left.Sequence, left.Kind, left.BaseCommit, left.TipCommit)
	rightKey := fmt.Sprintf("%s\x00%020d\x00%s\x00%s\x00%s", right.RepositoryUUID, right.Sequence, right.Kind, right.BaseCommit, right.TipCommit)
	return leftKey < rightKey
}

func verifyRecoveryCandidates(ctx context.Context, client *objectstore.Client, candidates []recoveryCandidate, exactTip string, secretKey []byte, workspace string, reserveBytes uint64, retainRepository bool) ([]verifiedRecovery, []string, error) {
	candidateTips := make(map[string]bool)
	for _, candidate := range candidates {
		candidateTips[candidate.TipCommit] = true
	}
	var tips []string
	if exactTip != "" {
		tips = []string{exactTip}
	} else {
		maximumSequence := make(map[string]uint64)
		for _, candidate := range candidates {
			if observed, ok := maximumSequence[candidate.TipCommit]; !ok || candidate.Sequence > observed {
				maximumSequence[candidate.TipCommit] = candidate.Sequence
			}
		}
		for tip := range maximumSequence {
			tips = append(tips, tip)
		}
		sort.Slice(tips, func(left, right int) bool {
			leftSequence, rightSequence := maximumSequence[tips[left]], maximumSequence[tips[right]]
			if leftSequence != rightSequence {
				return leftSequence > rightSequence
			}
			return tips[left] < tips[right]
		})
	}

	covered := make(map[string]bool)
	materializations := 0
	var commitRecords uint64
	var verified []verifiedRecovery
	var failures []string
	retained := -1
	ambiguous := false
	for _, tip := range tips {
		if exactTip == "" && covered[tip] {
			continue
		}
		paths, err := recoveryLogicalPaths(candidates, tip)
		if err != nil {
			return nil, failures, err
		}
		if len(paths) == 0 {
			failures = appendRecoveryFailure(failures, fmt.Sprintf("tip %s has no complete logical path", tip))
			continue
		}
		accepted := false
		for pathIndex, path := range paths {
			materializations++
			if materializations > maximumRecoveryMaterializations {
				return nil, failures, fmt.Errorf("recovery exceeds %d quarantine materializations; select an exact --tip", maximumRecoveryMaterializations)
			}
			if err := ctx.Err(); err != nil {
				return nil, failures, err
			}
			attemptRoot, err := os.MkdirTemp(workspace, "candidate-*")
			if err != nil {
				return nil, failures, err
			}
			if err := os.Chmod(attemptRoot, 0o700); err != nil {
				_ = removeTreeNoFollow(attemptRoot)
				return nil, failures, err
			}
			requiredBytes, requiredInodes, err := recoveryWorkspaceRequirement(path)
			if err != nil {
				_ = removeTreeNoFollow(attemptRoot)
				return nil, failures, err
			}
			if err := requireWorkspaceCapacity(attemptRoot, requiredBytes, requiredInodes, reserveBytes); err != nil {
				_ = removeTreeNoFollow(attemptRoot)
				return nil, failures, fmt.Errorf("recovery verification workspace: %w", err)
			}
			quarantine, history, attemptErr := materializeAndValidateRecoveryPath(ctx, client, path, secretKey, attemptRoot, tip)
			if attemptErr != nil {
				if err := removeTreeNoFollow(attemptRoot); err != nil {
					return nil, failures, err
				}
				failures = appendRecoveryFailure(failures, fmt.Sprintf("tip %s path %d: %v", tip, pathIndex, attemptErr))
				continue
			}
			commitIDsPath := filepath.Join(workspace, fmt.Sprintf("verified-%08d.ids", len(verified)))
			walkErr := writeRecoveryCommitIDs(history, commitIDsPath, candidateTips, covered, &commitRecords)
			// Retain at most one verified repository, not one per candidate tip.
			// Valid histories are linear: a second independent maximal tip cannot
			// later be joined by an accepted merge, so ambiguity needs only IDs.
			if walkErr == nil && retainRepository && !ambiguous && retained >= 0 {
				_, contains, err := history.IndexOf(verified[retained].Tip)
				walkErr = err
				if walkErr == nil {
					ambiguous = !contains
					walkErr = removeTreeNoFollow(filepath.Dir(verified[retained].RepositoryPath))
					verified[retained].RepositoryPath = ""
					retained = -1
				}
			}
			closeErr := history.Close()
			if walkErr != nil {
				return nil, failures, walkErr
			}
			if closeErr != nil {
				return nil, failures, closeErr
			}
			if retainRepository && !ambiguous {
				retained = len(verified)
			} else {
				if err := removeTreeNoFollow(attemptRoot); err != nil {
					return nil, failures, err
				}
				quarantine = ""
			}
			verified = append(verified, verifiedRecovery{Tip: tip, RepositoryPath: quarantine, CommitIDsPath: commitIDsPath})
			accepted = true
			break
		}
		if !accepted {
			failures = appendRecoveryFailure(failures, fmt.Sprintf("tip %s has no usable logical path", tip))
		}
	}
	return verified, failures, nil
}

func writeRecoveryCommitIDs(history *repository.History, path string, candidateTips, covered map[string]bool, total *uint64) error {
	if total == nil {
		return fmt.Errorf("recovery commit-record counter is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(file, 256<<10)
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := history.WalkIDs(func(_ int, commitID string) error {
		if *total >= maximumRecoveryCommitRecords {
			return fmt.Errorf("verified recovery histories exceed %d total commit records", maximumRecoveryCommitRecords)
		}
		*total = *total + 1
		if candidateTips[commitID] {
			covered[commitID] = true
		}
		_, err := fmt.Fprintln(writer, commitID)
		return err
	}); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func reportAvailableRecoveries(verified []verifiedRecovery, workspace string, report func(RecoverEvent) error) (uint64, error) {
	if len(verified) == 0 {
		return 0, nil
	}
	inputs := make([]string, len(verified))
	for index := range verified {
		inputs[index] = verified[index].CommitIDsPath
	}
	sorted := filepath.Join(workspace, "available-commits.sorted")
	if err := extsort.SortFiles(workspace, inputs, sorted, extsort.Options{MaxLineBytes: 64}); err != nil {
		return 0, err
	}
	file, err := os.Open(sorted)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65), 65)
	var count uint64
	previous := ""
	for scanner.Scan() {
		commitID := scanner.Text()
		if !isCommitID(commitID) {
			return count, fmt.Errorf("file-backed recovery commit set changed")
		}
		if commitID == previous {
			continue
		}
		previous = commitID
		count++
		if report != nil {
			if err := report(RecoverEvent{AvailableTip: commitID}); err != nil {
				return count, err
			}
		}
	}
	return count, scanner.Err()
}

func walkRecoveryCommitIDs(path string, visit func(string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65), 65)
	for scanner.Scan() {
		commitID := scanner.Text()
		if !isCommitID(commitID) {
			return fmt.Errorf("file-backed recovery commit set changed")
		}
		if err := visit(commitID); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func materializeAndValidateRecoveryPath(ctx context.Context, client *objectstore.Client, path recoveryPath, secretKey []byte, root, expectedTip string) (string, *repository.History, error) {
	bundleStage := filepath.Join(root, "bundles")
	if err := os.Mkdir(bundleStage, 0o700); err != nil {
		return "", nil, err
	}
	quarantine := filepath.Join(root, "repository.git")
	chosen, err := materializeMetadataChain(ctx, client, path.Edges, secretKey, quarantine, bundleStage)
	if err != nil {
		return "", nil, err
	}
	history, err := (repository.Validator{Repo: quarantine, Limits: format.DefaultLimits()}).ValidateHistory("refs/backup/recovered-tip")
	if err != nil {
		return "", nil, fmt.Errorf("validate recovered metadata history: %w", err)
	}
	if err := validateRecoveredManifestPath(chosen, history, expectedTip); err != nil {
		_ = history.Close()
		return "", nil, err
	}
	return quarantine, history, nil
}

func validateRecoveredManifestPath(chosen []manifestRepresentation, history *repository.History, expectedTip string) error {
	if len(chosen) == 0 || history == nil || history.Len() == 0 {
		return fmt.Errorf("recovered repository does not end at the declared tip")
	}
	tip, err := history.Tip()
	if err != nil || tip.CommitID != expectedTip {
		return fmt.Errorf("recovered repository does not end at the declared tip")
	}
	genesisFormat, err := history.GenesisFormat()
	if err != nil {
		return err
	}
	repositoryUUID := genesisFormat.RepositoryUUID
	firstSequence := chosen[0].Manifest.Sequence
	lastSequence := chosen[len(chosen)-1].Manifest.Sequence
	if lastSequence >= uint64(history.Len()) || lastSequence != uint64(history.Len()-1) || firstSequence >= uint64(history.Len()) {
		return fmt.Errorf("metadata manifest sequence disagrees with reconstructed Git history")
	}
	if uint64(len(chosen)-1) != lastSequence-firstSequence {
		return fmt.Errorf("metadata manifest path has a sequence gap")
	}
	for index, representation := range chosen {
		manifest := representation.Manifest
		sequence := firstSequence + uint64(index)
		commitID, err := history.CommitID(int(sequence))
		if err != nil {
			return err
		}
		if manifest.RepositoryUUID != repositoryUUID || manifest.Sequence != sequence || commitID != manifest.TipCommit {
			return fmt.Errorf("metadata manifest path disagrees with reconstructed Git identity or sequence")
		}
		if index == 0 {
			if manifest.Kind != format.BundleFull || manifest.BaseCommit != "-" {
				return fmt.Errorf("metadata manifest path does not begin with a full checkpoint")
			}
			continue
		}
		previous := chosen[index-1].Manifest
		baseID, err := history.CommitID(int(sequence) - 1)
		if err != nil {
			return err
		}
		if manifest.Kind != format.BundleIncremental || manifest.BaseCommit != previous.TipCommit || baseID != manifest.BaseCommit {
			return fmt.Errorf("metadata manifest path contains an incompatible incremental edge")
		}
	}
	return nil
}

func maximalVerifiedRecoveries(verified []verifiedRecovery) ([]verifiedRecovery, error) {
	verifiedTips := make(map[string]bool, len(verified))
	for _, candidate := range verified {
		verifiedTips[candidate.Tip] = true
	}
	ancestors := make(map[string]bool, len(verified))
	for _, descendant := range verified {
		if err := walkRecoveryCommitIDs(descendant.CommitIDsPath, func(commitID string) error {
			if commitID != descendant.Tip && verifiedTips[commitID] {
				ancestors[commitID] = true
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	maximal := make([]verifiedRecovery, 0, len(verified))
	for _, candidate := range verified {
		if !ancestors[candidate.Tip] {
			maximal = append(maximal, candidate)
		}
	}
	return maximal, nil
}

func appendRecoveryFailure(failures []string, detail string) []string {
	if len(failures) < maximumRecoveryFailureDetails {
		return append(failures, terminalEscape(detail))
	}
	return failures
}

func summarizeRecoveryFailures(failures []string) string {
	if len(failures) == 0 {
		return "no candidate path validated"
	}
	return strings.Join(failures, "; ")
}
