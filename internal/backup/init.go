package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/repository"
	"golang.org/x/sys/unix"
)

func Init(ctx context.Context, options Options, request InitRequest) (SnapshotResult, error) {
	normalized, err := options.normalized()
	if err != nil {
		return SnapshotResult{}, err
	}
	initializationLock, err := acquireInitializationLock(normalized.Root)
	if err != nil {
		return SnapshotResult{}, err
	}
	defer func() { _ = initializationLock.Close() }()
	config, err := localconfig.Load(normalized.ConfigPath)
	if err != nil {
		return SnapshotResult{}, err
	}
	repositoryPath := normalized.repositoryPath()
initialize:
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git")); statErr == nil {
		run, err := openRuntime(normalized, true)
		if err != nil {
			return SnapshotResult{}, err
		}
		defer func() { _ = run.close() }()
		txn, err := run.loadTransaction()
		if err != nil {
			return SnapshotResult{}, err
		}
		if txn == nil {
			_, exists, headErr := run.repo.HeadIfExists()
			if headErr != nil {
				return SnapshotResult{}, headErr
			}
			if exists {
				return SnapshotResult{}, fmt.Errorf("metadata repository already exists")
			}
			if err := run.close(); err != nil {
				return SnapshotResult{}, err
			}
			if err := removeTreeNoFollow(repositoryPath); err != nil {
				return SnapshotResult{}, fmt.Errorf("remove incomplete empty metadata repository: %w", err)
			}
			goto initialize
		}
		if txn.Kind != "genesis" {
			return SnapshotResult{}, fmt.Errorf("metadata repository already exists")
		}
		return run.commitTransaction(ctx, txn)
	} else if !os.IsNotExist(statErr) {
		return SnapshotResult{}, statErr
	}
	if len(request.RecoveryPublicKey) != 32 {
		return SnapshotResult{}, fmt.Errorf("a 32-byte permanent recovery public key is required")
	}
	keys := cloneKeys(request.PublicKeys)
	found := false
	for _, key := range keys {
		if string(key) == string(request.RecoveryPublicKey) {
			found = true
		}
	}
	if !found {
		keys = append(keys, append([]byte(nil), request.RecoveryPublicKey...))
	}
	sort.Slice(keys, func(left, right int) bool { return string(keys[left]) < string(keys[right]) })
	publicKeyBytes, err := format.MarshalPublicKeys(keys)
	if err != nil {
		return SnapshotResult{}, err
	}
	uuid, err := randomUUID()
	if err != nil {
		return SnapshotResult{}, err
	}
	repositoryFormat := format.NewRepositoryFormat(uuid, format.RecoveryFingerprint(request.RecoveryPublicKey))
	formatBytes, err := repositoryFormat.MarshalText()
	if err != nil {
		return SnapshotResult{}, err
	}
	mirrors := make([]format.Mirror, len(config.Mirrors))
	for index, mirror := range config.Mirrors {
		mirrors[index] = mirror.Canonical
	}
	mirrorBytes, err := format.MarshalMirrors(mirrors)
	if err != nil {
		return SnapshotResult{}, err
	}
	blobs := map[string][]byte{
		"FORMAT":      formatBytes,
		"index.tsv":   {},
		"objects.tsv": {},
		"packs.tsv":   {},
		"ignore":      {},
		".publickeys": publicKeyBytes,
		"mirrors.tsv": mirrorBytes,
	}
	repo, err := repository.Initialize(repositoryPath, config.GitRemote, config.Branch)
	if err != nil {
		return SnapshotResult{}, err
	}
	run := &runtime{options: normalized, config: config, repo: repo}
	if err := run.openStateAndLock(); err != nil {
		return SnapshotResult{}, err
	}
	defer func() { _ = run.close() }()
	if err := run.prepareTransactionFiles(); err != nil {
		return SnapshotResult{}, err
	}
	txn := newTransaction("genesis", "", normalized.Now().UTC())
	if err := run.stageCandidateBlobs(&txn, blobs); err != nil {
		return SnapshotResult{}, err
	}
	if err := run.saveTransaction(&txn); err != nil {
		return SnapshotResult{}, err
	}
	if err := run.checkpoint("genesis-transaction-recorded"); err != nil {
		return SnapshotResult{}, err
	}
	return run.commitTransaction(ctx, &txn)
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

func cloneKeys(keys [][]byte) [][]byte {
	result := make([][]byte, len(keys))
	for index, key := range keys {
		result[index] = append([]byte(nil), key...)
	}
	return result
}
