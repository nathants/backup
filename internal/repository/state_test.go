package repository

import (
	"bytes"
	"strings"
	"testing"

	"backup/internal/format"
)

const (
	plainHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	packHash  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	partHash  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	partSHA   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	partMD5   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	objectID  = "11111111111111111111111111111111"
)

func TestStateRequiresExactlySevenCanonicalBlobs(t *testing.T) {
	blobs := validGenesisBlobs(t)
	state, err := ParseState(blobs, format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ValidateGenesis(); err != nil {
		t.Fatal(err)
	}

	delete(blobs, "ignore")
	if _, err := ParseState(blobs, format.DefaultLimits()); err == nil {
		t.Fatal("accepted a missing required blob")
	}
	blobs = validGenesisBlobs(t)
	blobs["extra"] = nil
	if _, err := ParseState(blobs, format.DefaultLimits()); err == nil {
		t.Fatal("accepted an extra blob")
	}
}

func TestRecoveryRecipientIsPermanent(t *testing.T) {
	blobs := validGenesisBlobs(t)
	blobs[".publickeys"] = []byte(strings.Repeat("1", 64) + "\n")
	if _, err := ParseState(blobs, format.DefaultLimits()); err == nil {
		t.Fatal("accepted a state without the permanent recovery recipient")
	}
}

func TestOrdinaryAndRepairTransitions(t *testing.T) {
	oldState := parseState(t, validGenesisBlobs(t))
	newBlobs := cloneBlobs(validGenesisBlobs(t))
	index := []format.IndexEntry{{Path: "./a", Kind: format.KindFile, Ref: "blake2b:" + plainHash, Size: 3, Mode: 0o600, MtimeNS: 2}}
	objects := []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}}
	packs := []format.PackEntry{{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}}
	newBlobs["index.tsv"] = mustIndex(t, index)
	newBlobs["objects.tsv"] = mustObjects(t, objects)
	newBlobs["packs.tsv"] = mustPacks(t, packs)
	newState := parseState(t, newBlobs)
	kind, err := ValidateTransition(oldState, newState)
	if err != nil || kind != TransitionOrdinary {
		t.Fatalf("ordinary transition: kind=%v err=%v", kind, err)
	}

	repairBlobs := cloneBlobs(newBlobs)
	packs[0].ObjectID = "22222222222222222222222222222222"
	repairBlobs["packs.tsv"] = mustPacks(t, packs)
	repairState := parseState(t, repairBlobs)
	kind, err = ValidateTransition(newState, repairState)
	if err != nil || kind != TransitionRepair {
		t.Fatalf("repair transition: kind=%v err=%v", kind, err)
	}

	mixedBlobs := cloneBlobs(repairBlobs)
	index[0].MtimeNS++
	mixedBlobs["index.tsv"] = mustIndex(t, index)
	mixedState := parseState(t, mixedBlobs)
	if _, err := ValidateTransition(newState, mixedState); err == nil {
		t.Fatal("accepted a mixed repair and snapshot transition")
	}
}

func TestCatalogRowsAreImmutable(t *testing.T) {
	genesis := parseState(t, validGenesisBlobs(t))
	baseBlobs := cloneBlobs(validGenesisBlobs(t))
	baseBlobs["index.tsv"] = mustIndex(t, []format.IndexEntry{{Path: "./a", Kind: format.KindFile, Ref: "blake2b:" + plainHash, Size: 3, Mode: 0o600}})
	baseBlobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}})
	baseBlobs["packs.tsv"] = mustPacks(t, []format.PackEntry{{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}})
	base := parseState(t, baseBlobs)
	if _, err := ValidateTransition(genesis, base); err != nil {
		t.Fatal(err)
	}

	mutations := []func(map[string][]byte){
		func(blobs map[string][]byte) {
			blobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 4, PackHash: packHash}})
		},
		func(blobs map[string][]byte) {
			blobs["objects.tsv"] = nil
		},
		func(blobs map[string][]byte) {
			blobs["packs.tsv"] = mustPacks(t, []format.PackEntry{{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: strings.Repeat("f", 64), PartMD5: partMD5, PartSize: 10, ObjectID: objectID}})
		},
		func(blobs map[string][]byte) {
			blobs["FORMAT"] = bytes.Replace(blobs["FORMAT"], []byte("zstd"), []byte("gzip"), 1)
		},
	}
	for index, mutate := range mutations {
		blobs := cloneBlobs(baseBlobs)
		mutate(blobs)
		candidate, err := ParseState(blobs, format.DefaultLimits())
		if err == nil {
			_, err = ValidateTransition(base, candidate)
		}
		if err == nil {
			t.Fatalf("mutation %d was accepted", index)
		}
	}
}

func TestHistoricalCatalogCompatibilityAllowsOnlyRelocation(t *testing.T) {
	baseBlobs := validGenesisBlobs(t)
	baseBlobs["index.tsv"] = mustIndex(t, []format.IndexEntry{{Path: "./a", Kind: format.KindFile, Ref: "blake2b:" + plainHash, Size: 3, Mode: 0o600}})
	baseBlobs["objects.tsv"] = mustObjects(t, []format.ObjectEntry{{PlaintextHash: plainHash, PlaintextSize: 3, PackHash: packHash}})
	basePacks := []format.PackEntry{{PackHash: packHash, PartCount: 1, PartHash: partHash, PartSHA256: partSHA, PartMD5: partMD5, PartSize: 10, ObjectID: objectID}}
	baseBlobs["packs.tsv"] = mustPacks(t, basePacks)
	base := parseState(t, baseBlobs)

	laterPacks := append([]format.PackEntry(nil), basePacks...)
	laterPacks[0].ObjectID = "22222222222222222222222222222222"
	laterBlobs := cloneBlobs(baseBlobs)
	laterBlobs["packs.tsv"] = mustPacks(t, laterPacks)
	if err := ValidateCatalogStateForSnapshot(base, parseState(t, laterBlobs)); err != nil {
		t.Fatalf("compatible relocation rejected: %v", err)
	}
	laterPacks[0].PartSize++
	laterBlobs["packs.tsv"] = mustPacks(t, laterPacks)
	if err := ValidateCatalogStateForSnapshot(base, parseState(t, laterBlobs)); err == nil {
		t.Fatal("accepted incompatible alternate catalog")
	}
}

func validGenesisBlobs(t *testing.T) map[string][]byte {
	t.Helper()
	key := make([]byte, 32)
	repositoryFormat := format.NewRepositoryFormat("123e4567-e89b-42d3-a456-426614174000", "11111111111111111111111111111111", format.RecoveryFingerprint(key))
	formatBytes, err := repositoryFormat.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	publicKeys, err := format.MarshalPublicKeys([][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	mirrors, err := format.MarshalMirrors([]format.Mirror{{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: "https://localhost:8443", Region: "us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"FORMAT": formatBytes, "index.tsv": {}, "objects.tsv": {}, "packs.tsv": {},
		"ignore": {}, ".publickeys": publicKeys, "mirrors.tsv": mirrors,
	}
}

func parseState(t *testing.T, blobs map[string][]byte) State {
	t.Helper()
	state, err := ParseState(blobs, format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func cloneBlobs(input map[string][]byte) map[string][]byte {
	output := make(map[string][]byte, len(input))
	for name, data := range input {
		output[name] = append([]byte(nil), data...)
	}
	return output
}

func mustIndex(t *testing.T, entries []format.IndexEntry) []byte {
	t.Helper()
	data, err := format.MarshalIndex(entries)
	return mustBytes(t, data, err)
}

func mustObjects(t *testing.T, entries []format.ObjectEntry) []byte {
	t.Helper()
	data, err := format.MarshalObjects(entries)
	return mustBytes(t, data, err)
}

func mustPacks(t *testing.T, entries []format.PackEntry) []byte {
	t.Helper()
	data, err := format.MarshalPacks(entries)
	return mustBytes(t, data, err)
}

func mustBytes(t *testing.T, data []byte, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
