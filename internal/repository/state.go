package repository

import (
	"fmt"

	"backup/internal/format"
)

var RequiredBlobNames = []string{".publickeys", "FORMAT", "ignore", "index.tsv", "mirrors.tsv", "objects.tsv", "packs.tsv"}

type State struct {
	Format     format.RepositoryFormat
	Ignore     format.Ignore
	PublicKeys [][]byte
	Mirrors    []format.Mirror

	source      stateSource
	BlobHashes  map[string]string
	BlobSizes   map[string]uint64
	IndexCount  uint64
	ObjectCount uint64
	PackCount   uint64
}

// ParseState is the convenience entry point for callers that already own all
// seven blobs in memory. Validation itself uses the same streaming parser as
// Git-backed and file-backed states.
func ParseState(blobs map[string][]byte, limits format.Limits) (State, error) {
	if len(blobs) != len(RequiredBlobNames) {
		return State{}, fmt.Errorf("metadata tree contains %d blobs, expected exactly %d", len(blobs), len(RequiredBlobNames))
	}
	copied := make(memoryStateSource, len(blobs))
	for _, name := range RequiredBlobNames {
		data, ok := blobs[name]
		if !ok {
			return State{}, fmt.Errorf("metadata tree is missing required blob %q", name)
		}
		copied[name] = append([]byte(nil), data...)
	}
	for name := range blobs {
		if _, ok := copied[name]; !ok {
			return State{}, fmt.Errorf("metadata tree contains unexpected blob %q", name)
		}
	}
	return parseStreamState(copied, limits)
}

func (state State) Validate() error {
	if state.source == nil || len(state.BlobHashes) != len(RequiredBlobNames) || len(state.BlobSizes) != len(RequiredBlobNames) {
		return fmt.Errorf("metadata state is incomplete")
	}
	if err := format.RequireRecoveryRecipient(state.PublicKeys, state.Format.RecoveryRecipientFingerprint); err != nil {
		return err
	}
	return nil
}

func (state State) ValidateGenesis() error {
	if err := state.Validate(); err != nil {
		return err
	}
	if state.BlobSizes["index.tsv"] != 0 || state.BlobSizes["objects.tsv"] != 0 || state.BlobSizes["packs.tsv"] != 0 {
		return fmt.Errorf("genesis catalogs and snapshot must be empty")
	}
	if len(state.Mirrors) == 0 {
		return fmt.Errorf("genesis must configure at least one mirror")
	}
	return nil
}

type TransitionKind int

const (
	TransitionInvalid TransitionKind = iota
	TransitionOrdinary
	TransitionRepair
)

func ValidateTransition(oldState, newState State) (TransitionKind, error) {
	return validateStreamTransition(oldState, newState)
}

func statesEqual(left, right State) bool {
	for _, name := range RequiredBlobNames {
		if !left.blobEqual(right, name) {
			return false
		}
	}
	return true
}

func validateMirrorImmediateIdentity(oldMirrors, newMirrors []format.Mirror) error {
	oldByName := make(map[string]format.Mirror, len(oldMirrors))
	for _, mirror := range oldMirrors {
		oldByName[mirror.Name] = mirror
	}
	for _, mirror := range newMirrors {
		if previous, ok := oldByName[mirror.Name]; ok && previous != mirror {
			return fmt.Errorf("mirror %q was rebound", mirror.Name)
		}
	}
	return nil
}
