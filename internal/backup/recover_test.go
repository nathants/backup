package backup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/repository"
	"github.com/nathants/go-libsodium"
)

type recoveryProbe struct {
	transport http.RoundTripper
	mu        sync.Mutex
	gets      map[string]int
	observe   func() error
}

func (probe *recoveryProbe) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/metadata/parts/") {
		probe.mu.Lock()
		probe.gets[request.URL.Path]++
		probe.mu.Unlock()
		if probe.observe != nil {
			if err := probe.observe(); err != nil {
				return nil, err
			}
		}
	}
	return probe.transport.RoundTrip(request)
}

func observeRecoveryRequests(harness *integrationHarness) *recoveryProbe {
	client := harness.http.Client()
	probe := &recoveryProbe{transport: client.Transport, gets: make(map[string]int)}
	client.Transport = probe
	return probe
}

func recoveryTestChain(t *testing.T, length int) (*integrationHarness, [][]manifestRepresentation) {
	t.Helper()
	harness := newIntegrationHarness(t)
	// Small multipart fixtures exercise part accounting without hundreds of PUTs.
	harness.options.MetadataPartSize = 1024
	ctx := context.Background()
	genesis, err := initializePublished(ctx, harness.options, InitRequest{RecoveryPublicKey: harness.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	repo := &repository.Managed{Directory: filepath.Join(harness.root, ".backup")}
	history, err := (repository.Validator{Repo: repo.Directory, Limits: format.DefaultLimits()}).ValidateHistory(genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	uuid := testHistoryGenesisFormat(t, history).RepositoryUUID
	blobs := testStateBlobs(t, testHistoryTip(t, history).State)
	client := testMirrorClient(t, ctx, harness)
	first, err := listManifestRepresentations(ctx, client, genesis.CommitID, uuid)
	if err != nil || len(first) != 1 {
		t.Fatalf("genesis representations=%d err=%v", len(first), err)
	}
	chain := [][]manifestRepresentation{first}
	base := genesis.CommitID
	for sequence := 1; sequence < length; sequence++ {
		blobs["ignore"] = fmt.Appendf(nil, "^\\./revision-%d$\n", sequence)
		tip, err := repo.CreateCommit(base, blobs, fmt.Sprintf("recovery fixture %d", sequence))
		if err != nil {
			t.Fatal(err)
		}
		representation := uploadTestMetadataBundle(t, ctx, client, repo, uuid, base, tip, uint64(sequence), harness.publicKey, harness.options.MetadataPartSize)
		chain = append(chain, []manifestRepresentation{representation})
		base = tip
	}
	return harness, chain
}

func TestRecoverPublishesVerifiedRepositoryWithoutReread(t *testing.T) {
	for _, anchored := range []bool{false, true} {
		t.Run(fmt.Sprint(anchored), func(t *testing.T) {
			harness, chain := recoveryTestChain(t, 3)
			probe := observeRecoveryRequests(harness)
			t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
			if err := os.Rename(harness.bare, harness.bare+"-offline"); err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			want := chain[len(chain)-1][0].Manifest.TipCommit
			request := RecoverRequest{Mirror: "local", Destination: filepath.Join(parent, "recovered.git")}
			if anchored {
				request.Tip = want
			}
			reported := 0
			request.Report = func(event RecoverEvent) error {
				reported++
				if reported == 1 {
					// The complete chain is already verified when reporting begins.
					// Publication must not depend on another remote read.
					harness.http.Close()
				}
				return nil
			}
			result, err := Recover(context.Background(), harness.options, request)
			if err != nil || result.RecoveredTip != want || result.Available != 3 || reported != 3 {
				t.Fatalf("publication after mirror outage: result=%#v reports=%d err=%v", result, reported, err)
			}
			history, err := (repository.Validator{Repo: request.Destination, Limits: format.DefaultLimits()}).ValidateHistory("refs/backup/recovered-tip")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = history.Close() }()
			if history.Len() != len(chain) || testHistoryTip(t, history).CommitID != want {
				t.Fatal("published repository differs from the verified chain")
			}
			probe.mu.Lock()
			defer probe.mu.Unlock()
			for _, alternatives := range chain {
				for _, part := range alternatives[0].Manifest.Parts {
					key, err := format.MetadataPartKey(part)
					if err != nil {
						t.Fatal(err)
					}
					if count := probe.gets["/backup-test/repository/"+key]; count != 1 {
						t.Errorf("part %s downloaded %d times, want once", key, count)
					}
				}
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "recovered.git" {
				t.Fatalf("publication left staging: %v err=%v", entries, err)
			}
		})
	}
}

func TestMetadataRecoveryUsesOneRepositoryForHealthyChain(t *testing.T) {
	harness, chain := recoveryTestChain(t, 3)
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	probe := observeRecoveryRequests(harness)
	var first os.FileInfo
	probe.observe = func() error {
		var repositories []os.FileInfo
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".git") {
				info, err := entry.Info()
				if err != nil {
					return err
				}
				repositories = append(repositories, info)
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(repositories) != 1 {
			t.Errorf("healthy import retained %d repositories, want one", len(repositories))
		} else if first == nil {
			first = repositories[0]
		} else if !os.SameFile(first, repositories[0]) {
			t.Error("healthy import replaced the accepted repository instead of extending it")
		}
		return nil
	}
	reader := testMirrorClient(t, context.Background(), harness)
	quarantine := filepath.Join(root, "recovered.git")
	chosen, err := materializeMetadataChain(context.Background(), reader, chain, harness.secretKey, quarantine, stage)
	if err != nil || len(chosen) != len(chain) {
		t.Fatalf("healthy materialization: chosen=%d err=%v", len(chosen), err)
	}
}

// Construct a correctly framed native Git bundle whose pack contains one extra
// unreachable blob. Header/authentication failures must not mask import cleanup.
func recoveryBundleWithExtraObject(t *testing.T, repo *repository.Managed, base, tip string) ([]byte, string) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "valid.bundle")
	if err := repo.CreateBundle(base, tip, bundlePath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.Index(data, []byte("\n\n"))
	if headerEnd < 0 {
		t.Fatal("native Git bundle has no header terminator")
	}
	extraBytes, err := repo.RunGit([]byte("unreachable recovery-test object"), 1024, "hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.TrimSpace(string(extraBytes))
	revisions := tip + "\n" + extra + "\n"
	if base != "" {
		revisions += "^" + base + "\n"
	}
	packed, err := repo.RunGit([]byte(revisions), 16<<20, "pack-objects", "--stdout", "--revs")
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), data[:headerEnd+2]...), packed...), extra
}

func uploadRecoveryTestBundle(t *testing.T, harness *integrationHarness, manifest format.MetadataManifest, bundle []byte) manifestRepresentation {
	t.Helper()
	var encrypted bytes.Buffer
	if err := libsodium.StreamEncryptRecipients([][]byte{harness.publicKey}, bytes.NewReader(bundle), &encrypted); err != nil {
		t.Fatal(err)
	}
	data := encrypted.Bytes()
	identity := objectstore.HashBytes(data)
	manifest.BundleHash, manifest.BundleSize = identity.BLAKE2b, identity.Size
	manifest.Parts = []format.ManifestPart{{
		Number: 0, Count: 1, ObjectID: strings.Repeat("a", 32), Hash: identity.BLAKE2b,
		SHA256: identity.SHA256, MD5: identity.MD5, Size: identity.Size,
	}}
	partKey, err := format.MetadataPartKey(manifest.Parts[0])
	if err != nil {
		t.Fatal(err)
	}
	partPath := filepath.Join(t.TempDir(), "encrypted.bundle")
	if err := os.WriteFile(partPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writer := testMirrorClient(t, context.Background(), harness)
	if result := writer.PutFile(context.Background(), partKey, partPath, identity); result.Disposition != objectstore.CreateAcknowledged {
		t.Fatalf("upload malformed bundle: %#v", result)
	}
	return uploadTestManifest(t, context.Background(), writer, manifest, strings.Repeat("b", 32))
}

func TestMetadataRecoveryReplaysAfterImportedObjectFailure(t *testing.T) {
	harness, chain := recoveryTestChain(t, 3)
	repo := &repository.Managed{Directory: filepath.Join(harness.root, ".backup")}
	manifest := chain[1][0].Manifest
	bundle, extra := recoveryBundleWithExtraObject(t, repo, manifest.BaseCommit, manifest.TipCommit)
	bad := uploadRecoveryTestBundle(t, harness, manifest, bundle)
	chain[1] = append([]manifestRepresentation{bad}, chain[1]...)

	// Prove the fixture passes framing, imports real objects, and only then
	// fails the strict graph check. A merely bad header would not exercise replay.
	fixture := filepath.Join(t.TempDir(), "bad.bundle")
	if err := os.WriteFile(fixture, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	assertValidRecoveryBundleHeader(t, fixture, manifest)
	check, err := initializeMetadataQuarantine(filepath.Join(t.TempDir(), "fixture.git"))
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(t.TempDir(), "genesis.bundle")
	if err := repo.CreateBundle("", manifest.BaseCommit, full); err != nil {
		t.Fatal(err)
	}
	if err := applyMetadataBundle(check, full, chain[0][0].Manifest, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := applyMetadataBundle(check, fixture, manifest, manifest.BaseCommit); err == nil || !strings.Contains(err.Error(), "outside its declared tip graph") {
		t.Fatalf("fixture did not reach graph validation: %v", err)
	}
	if _, err := check.RunGit(nil, 1024, "cat-file", "-e", extra); err != nil {
		t.Fatalf("fixture did not contaminate the failed repository: %v", err)
	}

	probe := observeRecoveryRequests(harness)
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	reader := testMirrorClient(t, context.Background(), harness)
	quarantine := filepath.Join(root, "recovered.git")
	chosen, err := materializeMetadataChain(context.Background(), reader, chain, harness.secretKey, quarantine, stage)
	if err != nil || len(chosen) != 3 || chosen[1].Key == bad.Key {
		t.Fatalf("healthy alternate was not selected: chosen=%d err=%v", len(chosen), err)
	}
	clean := &repository.Managed{Directory: quarantine}
	if _, err := clean.RunGit(nil, 1024, "cat-file", "-e", extra); err == nil {
		t.Fatal("recovered repository retained the failed import's extra object")
	}
	probe.mu.Lock()
	defer probe.mu.Unlock()
	for edge, alternatives := range chain {
		for representation, alternative := range alternatives {
			for _, part := range alternative.Manifest.Parts {
				key, err := format.MetadataPartKey(part)
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if edge == 0 {
					want = 2 // The accepted prefix is replayed only after the bad import.
				}
				if got := probe.gets["/backup-test/repository/"+key]; got != want {
					t.Errorf("edge %d representation %d downloads=%d, want %d", edge, representation, got, want)
				}
			}
		}
	}
}

func TestRecoverDoesNotReplaceDestinationCreatedDuringReporting(t *testing.T) {
	harness, chain := recoveryTestChain(t, 1)
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	parent := t.TempDir()
	destination := filepath.Join(parent, "late.git")
	var created os.FileInfo
	request := RecoverRequest{Mirror: "local", Tip: chain[0][0].Manifest.TipCommit, Destination: destination,
		Report: func(RecoverEvent) error {
			if err := os.Mkdir(destination, 0o700); err != nil {
				return err
			}
			var err error
			created, err = os.Stat(destination)
			return err
		}}
	if _, err := Recover(context.Background(), harness.options, request); err == nil {
		t.Error("recovery replaced a destination that appeared before publication")
	}
	current, err := os.Stat(destination)
	if err != nil || created == nil || !os.SameFile(created, current) {
		t.Fatalf("pre-publication destination was not preserved: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "late.git" {
		t.Fatalf("refusal left recovery staging: %v err=%v", entries, err)
	}
}

func TestRecoverCleansRetainedRepositoryOnReportFailureAndCancellation(t *testing.T) {
	harness, chain := recoveryTestChain(t, 1)
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelRequest), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parent := t.TempDir()
			stop := fmt.Errorf("stop reporting")
			want := stop
			request := RecoverRequest{Mirror: "local", Tip: chain[0][0].Manifest.TipCommit, Destination: filepath.Join(parent, "recovered.git"),
				Report: func(RecoverEvent) error {
					if cancelRequest {
						cancel()
						return nil
					}
					return stop
				}}
			if cancelRequest {
				want = context.Canceled
			}
			if _, err := Recover(ctx, harness.options, request); !errors.Is(err, want) {
				t.Fatalf("recovery did not honor report interruption: %v", err)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("report interruption left published/staged files: %v err=%v", entries, err)
			}
		})
	}
}

func TestMetadataImportStrictlyRejectsMalformedCommitBeforeReachability(t *testing.T) {
	harness, chain := recoveryTestChain(t, 1)
	source := &repository.Managed{Directory: filepath.Join(harness.root, ".backup")}
	base := chain[0][0].Manifest.TipCommit
	tree, err := source.RunGit(nil, 1024, "rev-parse", base+"^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("tree %s\nparent %s\nauthor missing-email 1700000000 +0000\ncommitter Test <test@example.com> 1700000000 +0000\n\nbad author fixture\n", strings.TrimSpace(string(tree)), base)
	object, err := source.RunGit([]byte(body), 1024, "hash-object", "--literally", "-w", "-t", "commit", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	badTip := strings.TrimSpace(string(object))
	bundle := filepath.Join(t.TempDir(), "bad.bundle")
	if err := source.CreateBundle(base, badTip, bundle); err != nil {
		t.Fatal(err)
	}
	manifest := chain[0][0].Manifest
	manifest.Kind, manifest.BaseCommit, manifest.TipCommit, manifest.Sequence = format.BundleIncremental, base, badTip, 1
	assertValidRecoveryBundleHeader(t, bundle, manifest)
	quarantine, err := initializeMetadataQuarantine(filepath.Join(t.TempDir(), "check.git"))
	if err != nil {
		t.Fatal(err)
	}
	genesis := filepath.Join(t.TempDir(), "genesis.bundle")
	if err := source.CreateBundle("", base, genesis); err != nil {
		t.Fatal(err)
	}
	if err := applyMetadataBundle(quarantine, genesis, chain[0][0].Manifest, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := applyMetadataBundle(quarantine, bundle, manifest, base); err == nil || !strings.Contains(err.Error(), "strict pack validation") {
		t.Fatalf("malformed commit bypassed strict import: %v", err)
	}
	current, err := quarantine.RunGit(nil, 1024, "rev-parse", "refs/backup/recovered-tip")
	if err != nil || strings.TrimSpace(string(current)) != base {
		t.Fatalf("failed strict import advanced the accepted tip: %s err=%v", current, err)
	}
}

func TestMetadataRecoveryFinalCheckRejectsPreviouslyStoredBlobCorruption(t *testing.T) {
	harness, chain := recoveryTestChain(t, 3)
	source := &repository.Managed{Directory: filepath.Join(harness.root, ".backup")}
	priorTip := chain[1][0].Manifest.TipCommit
	blob, err := source.RunGit(nil, 1024, "rev-parse", priorTip+":ignore")
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.TrimSpace(string(blob))
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	lastKey, err := format.MetadataPartKey(chain[2][0].Manifest.Parts[0])
	if err != nil {
		t.Fatal(err)
	}
	probe := observeRecoveryRequests(harness)
	mutated := false
	probe.observe = func() error {
		probe.mu.Lock()
		lastStarted := probe.gets["/backup-test/repository/"+lastKey] > 0
		probe.mu.Unlock()
		if mutated || !lastStarted {
			return nil
		}
		mutated = true
		var repositoryPath string
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() && entry.Name() == "repository.git" {
				repositoryPath = path
				return filepath.SkipDir
			}
			return nil
		}); err != nil {
			return err
		}
		if repositoryPath == "" {
			return fmt.Errorf("accepted repository not found before final bundle")
		}
		repo := &repository.Managed{Directory: repositoryPath}
		wrong, err := repo.RunGit([]byte("^wrong-but-valid-ignore$\n"), 1024, "hash-object", "-w", "--stdin")
		if err != nil {
			return err
		}
		wrongID := strings.TrimSpace(string(wrong))
		directory := filepath.Join(repositoryPath, "objects", expected[:2])
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(repositoryPath, "objects", wrongID[:2], wrongID[2:]), filepath.Join(directory, expected[2:])); err != nil {
			return err
		}
		// This deliberate local-storage fault leaves a readable blob of the
		// correct type at the expected name. Connectivity alone must pass.
		if err := validateMetadataGraph(repo, priorTip, true); err != nil {
			return fmt.Errorf("fixture failed before full content verification: %w", err)
		}
		return nil
	}
	reader := testMirrorClient(t, context.Background(), harness)
	quarantine := filepath.Join(root, "recovered.git")
	_, err = materializeMetadataChain(context.Background(), reader, chain, harness.secretKey, quarantine, stage)
	if !mutated || err == nil || !strings.Contains(err.Error(), "validate bundle object graph") || strings.Contains(err.Error(), "no usable physical representation") {
		t.Fatalf("final content check did not reject stored corruption: mutated=%t err=%v", mutated, err)
	}
	if _, err := os.Stat(quarantine); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt repository was retained: %v", err)
	}
}

func assertValidRecoveryBundleHeader(t *testing.T, path string, manifest format.MetadataManifest) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := readMetadataBundleHeader(bufio.NewReaderSize(file, 4096), manifest); err != nil {
		t.Fatalf("fixture failed before object import: %v", err)
	}
}

func TestRecoverListingRetainsOnlyCommitIDs(t *testing.T) {
	harness, chain := recoveryTestChain(t, 2)
	t.Setenv("BACKUP_SECRET_KEY", fmt.Sprintf("%x", harness.secretKey))
	workspace := t.TempDir()
	t.Setenv("TMPDIR", workspace)
	reports := 0
	result, err := Recover(context.Background(), harness.options, RecoverRequest{Mirror: "local", ListOnly: true,
		Report: func(RecoverEvent) error {
			reports++
			return filepath.WalkDir(workspace, func(_ string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() && strings.HasSuffix(entry.Name(), ".git") {
					return fmt.Errorf("listing retained a Git repository after validation")
				}
				return nil
			})
		}})
	if err != nil || result.Available != uint64(len(chain)) || reports != len(chain) || result.Destination != "" {
		t.Fatalf("listing=%#v reports=%d err=%v", result, reports, err)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatalf("listing left temporary workspaces: %v err=%v", entries, err)
	}
}
