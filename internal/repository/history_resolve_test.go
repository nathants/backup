package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
)

func TestHistoryResolveRevisionPreservesStateAndTransitions(t *testing.T) {
	validator, ids, blobs := historyResolutionFixture(t)
	history, err := validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	cacheBefore, err := os.ReadFile(validator.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	runGitTest(t, validator.Repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "tag", "-a", "repair", ids[2], "-m", "historical repair")
	for _, test := range []struct {
		revision   string
		index      int
		transition TransitionKind
	}{
		{"", 3, TransitionOrdinary}, {"HEAD", 3, TransitionOrdinary},
		{ids[0], 0, TransitionInvalid}, {ids[1], 1, TransitionOrdinary},
		{ids[2], 2, TransitionRepair}, {ids[3], 3, TransitionOrdinary},
		{"HEAD~1", 2, TransitionRepair}, {"refs/tags/repair", 2, TransitionRepair},
		{ids[1][:12], 1, TransitionOrdinary}, {"main", 3, TransitionOrdinary},
	} {
		t.Run(test.revision, func(t *testing.T) {
			selected, err := history.ResolveRevision(test.revision)
			if err != nil {
				t.Fatal(err)
			}
			parent := ""
			if test.index > 0 {
				parent = ids[test.index-1]
			}
			if selected.CommitID != ids[test.index] || selected.ParentID != parent || selected.Transition != test.transition {
				t.Fatalf("selection identity/classification: commit=%s parent=%s transition=%v", selected.CommitID, selected.ParentID, selected.Transition)
			}
			if !selected.State.Equal(parseState(t, blobs[test.index])) {
				t.Fatal("selected state differs from the historical snapshot")
			}
		})
	}
	cacheAfter, err := os.ReadFile(validator.CachePath)
	if err != nil || string(cacheBefore) != string(cacheAfter) {
		t.Fatalf("historical selection changed the validated-ancestor cache: %v", err)
	}

	selected, err := history.ResolveRevision(ids[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := selected.State.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		count++
		if part.ObjectID != objectID {
			t.Fatalf("historical mapping changed: %s", part.ObjectID)
		}
		return nil
	}); err != nil || count != 1 {
		t.Fatalf("selected Git-backed state did not survive history cleanup: count=%d err=%v", count, err)
	}
	for _, unavailable := range []*History{nil, {}, history} {
		for _, revision := range []string{"", "HEAD", ids[0]} {
			if _, err := unavailable.ResolveRevision(revision); err == nil {
				t.Fatalf("unavailable history resolved %q", revision)
			}
		}
	}
}

func TestHistoryResolveRevisionRejectsUnacceptedCommits(t *testing.T) {
	validator, ids, blobs := historyResolutionFixture(t)
	history, err := validator.ValidateHistory("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	genesisTree := strings.TrimSpace(runGitTest(t, validator.Repo, "rev-parse", ids[0]+"^{tree}"))
	foreign := strings.TrimSpace(runGitTest(t, validator.Repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit-tree", genesisTree, "-m", "unaccepted genesis"))
	blobs[3]["ignore"] = []byte("^\\./new-config$\n")
	writeBlobs(t, validator.Repo, blobs[3])
	runGitTest(t, validator.Repo, "add", "--", "ignore")
	runGitTest(t, validator.Repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "unaccepted descendant")
	descendant := strings.TrimSpace(runGitTest(t, validator.Repo, "rev-parse", "HEAD"))
	for _, revision := range []string{foreign, descendant, "main", "HEAD~0"} {
		if _, err := history.ResolveRevision(revision); err == nil || !strings.Contains(err.Error(), "not in the validated primary history") {
			t.Fatalf("unaccepted revision %q: %v", revision, err)
		}
	}
	for _, revision := range []string{"", "HEAD"} {
		selected, err := history.ResolveRevision(revision)
		if err != nil || selected.CommitID != ids[3] {
			t.Fatalf("pinned tip followed a moved ref: selected=%s err=%v", selected.CommitID, err)
		}
	}
	for _, revision := range []string{"--all", "-HEAD", "HEAD\n", "HEAD\r", "HEAD\x00", "missing-ref", genesisTree} {
		if _, err := history.ResolveRevision(revision); err == nil {
			t.Fatalf("invalid/noncommit revision %q was accepted", revision)
		}
	}
}

func TestHistoryResolveRevisionRechecksSelectedObjects(t *testing.T) {
	for _, test := range []struct {
		name     string
		position int
	}{{"historical", 1}, {"tip", 3}} {
		t.Run(test.name, func(t *testing.T) {
			position := test.position
			validator, ids, _ := historyResolutionFixture(t)
			history, err := validator.ValidateHistory("HEAD")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = history.Close() }()
			blobID := strings.TrimSpace(runGitTest(t, validator.Repo, "rev-parse", ids[position]+":ignore"))
			path := filepath.Join(validator.Repo, ".git", "objects", blobID[:2], blobID[2:])
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("corrupt loose Git object"), 0o600); err != nil {
				t.Fatal(err)
			}
			if position == 1 {
				// A valid tip cache must not hide damage in an older selected
				// state whose distinct blob is absent from the current tree.
				if err := history.Close(); err != nil {
					t.Fatal(err)
				}
				history, err = validator.ValidateHistory("HEAD")
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := history.ResolveRevision(ids[position]); err == nil {
				t.Fatal("selected corrupt canonical object was accepted")
			}
		})
	}
}

func historyResolutionFixture(t *testing.T) (Validator, []string, []map[string][]byte) {
	t.Helper()
	repo := initTestRepo(t, "sha256")
	genesis := validGenesisBlobs(t)
	ordinary := cloneBlobs(genesis)
	ordinary["ignore"] = []byte("^\\./old-config$\n")
	ordinary["index.tsv"] = mustIndex(t, []format.IndexEntry{{Path: "./a", Kind: format.KindFile, Ref: "blake2b:" + plainHash, Size: 3, Mode: 0o600, MtimeNS: 2}})
	ordinary["objects.tsv"] = mustObjects(t, []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}})
	part := format.PackEntry{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}
	ordinary["packs.tsv"] = mustPacks(t, []format.PackEntry{part})
	repair := cloneBlobs(ordinary)
	part.ObjectID = strings.Repeat("2", 32)
	repair["packs.tsv"] = mustPacks(t, []format.PackEntry{part})
	latest := cloneBlobs(repair)
	latest["ignore"] = []byte("^\\./current-config$\n")
	states := []map[string][]byte{genesis, ordinary, repair, latest}
	var ids []string
	for _, blobs := range states {
		writeBlobs(t, repo, blobs)
		runGitTest(t, repo, "add", "--", ".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv")
		runGitTest(t, repo, "-c", "user.name=backup", "-c", "user.email=backup@invalid", "commit", "-m", "metadata")
		ids = append(ids, strings.TrimSpace(runGitTest(t, repo, "rev-parse", "HEAD")))
	}
	return Validator{Repo: repo, Limits: format.DefaultLimits(), CachePath: filepath.Join(t.TempDir(), "validated.json")}, ids, states
}
