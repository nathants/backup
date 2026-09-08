package backup

import (
	"context"
	"fmt"
	"os"

	"backup/internal/format"
	"backup/internal/objectstore"
	"backup/internal/repository"

	"golang.org/x/sys/unix"
)

func Init(ctx context.Context, options Options) (InitResult, error) {
	normalized, err := options.normalized()
	if err != nil {
		return InitResult{}, err
	}
	initializationLock, err := acquireInitializationLock(normalized.Root)
	if err != nil {
		return InitResult{}, err
	}
	defer func() { _ = initializationLock.Close() }()
	if err := ctx.Err(); err != nil {
		return InitResult{}, err
	}
	uuid, err := randomUUID()
	if err != nil {
		return InitResult{}, err
	}
	repositoryFormat := format.NewRepositoryFormat(uuid)
	formatBytes, err := repositoryFormat.MarshalText()
	if err != nil {
		return InitResult{}, err
	}
	blobs := map[string][]byte{
		"FORMAT":      formatBytes,
		"index.tsv":   {},
		"objects.tsv": {},
		"packs.tsv":   {},
		"ignore":      {},
		".publickeys": {},
		"mirrors.tsv": {},
	}
	// InitializeLocal requires an absent or empty real directory. On failure,
	// preserve setup residue for diagnosis; never remove ambiguous local state.
	repo, err := repository.InitializeLocal(normalized.repositoryPath())
	if err != nil {
		return InitResult{}, err
	}
	run := &runtime{options: normalized, repo: repo}
	if err := run.openStateAndLock(); err != nil {
		return InitResult{}, err
	}
	defer func() { _ = run.close() }()
	if err := repo.Materialize(blobs); err != nil {
		return InitResult{}, err
	}
	if err := run.checkpoint("initialization-prepared"); err != nil {
		return InitResult{}, err
	}
	preparation := preparation{Version: 1, FormatHash: objectstore.HashBytes(formatBytes).BLAKE2b}
	if err := run.store.Write(preparationFilename, &preparation); err != nil {
		return InitResult{}, err
	}
	if err := run.checkpoint("initialization-completed"); err != nil {
		return InitResult{}, err
	}
	return InitResult{RepositoryUUID: uuid}, nil
}

func acquireInitializationLock(root string) (*os.File, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open backup root for initialization lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), root)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another backup initialization is in progress: %w", err)
	}
	return file, nil
}
