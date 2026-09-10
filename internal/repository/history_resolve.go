package repository

import "fmt"

// ResolveRevision selects only commits in this already accepted history. Empty
// and HEAD select its pinned tip, not a newly resolved ref. Other expressions
// are resolved once, then the selected canonical state is reread and validated.
// Historical transition classification needs only the immediate parent; it
// never rewalks accepted ancestors or changes the validated-ancestor cache.
func (history *History) ResolveRevision(revision string) (ValidatedCommit, error) {
	tip, err := history.Tip()
	if err != nil {
		return ValidatedCommit{}, err
	}
	if revision == "" || revision == "HEAD" {
		return tip, nil
	}
	commitID, err := history.validator.resolveCommitID(revision)
	if err != nil {
		return ValidatedCommit{}, err
	}
	index, found, err := history.IndexOf(commitID)
	if err != nil {
		return ValidatedCommit{}, err
	}
	if !found {
		return ValidatedCommit{}, fmt.Errorf("revision %s is not in the validated primary history", commitID)
	}
	selected, err := history.validator.validateCommit(commitID)
	if err != nil {
		return ValidatedCommit{}, fmt.Errorf("commit %s: %w", commitID, err)
	}
	parentID := ""
	if index > 0 {
		parentID, err = history.CommitID(index - 1)
		if err != nil {
			return ValidatedCommit{}, err
		}
	}
	if selected.ParentID != parentID || selected.State.Format != history.genesisFormat {
		return ValidatedCommit{}, fmt.Errorf("selected commit disagrees with validated history")
	}
	switch {
	case commitID == tip.CommitID:
		if !equalBlobIDs(selected.BlobIDs, tip.BlobIDs) {
			return ValidatedCommit{}, fmt.Errorf("selected tip tree changed after validation")
		}
		selected.Transition = tip.Transition
	case index == 0:
		if err := selected.State.ValidateGenesis(); err != nil {
			return ValidatedCommit{}, fmt.Errorf("invalid genesis: %w", err)
		}
	default:
		parent, err := history.validator.validateCommit(parentID)
		if err != nil {
			return ValidatedCommit{}, fmt.Errorf("parent %s: %w", parentID, err)
		}
		selected.Transition, err = ValidateTransition(parent.State, selected.State)
		if err != nil {
			return ValidatedCommit{}, fmt.Errorf("invalid transition: %w", err)
		}
	}
	return selected, nil
}
