package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"backup/internal/extsort"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"
	"backup/internal/pack"
	"backup/internal/repository"
	"github.com/nathants/go-libsodium"
)

// Full verification streams local ciphertext through the actual pack reader;
// only bounded, file-backed catalog sorting uses temporary storage. Metadata
// recovery uses the same private Git import/validation path as recover.
func (run *runtime) verifyFull(ctx context.Context, mirror localconfig.Mirror, selected repository.ValidatedCommit, pending *transaction, secret *libsodium.Keyring) (returnErr error) {
	if mirror.Canonical.Kind != format.MirrorFilesystem {
		return fmt.Errorf("full verification requires a filesystem mirror; protocol mirrors are checksum-only")
	}
	client, err := run.client(ctx, mirror)
	if err != nil {
		return err
	}
	workspace, err := os.MkdirTemp("", "backup-full-verify-")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, removeTreeIfPresent(workspace)) }()
	if err := run.verifyFullPacks(ctx, client, mirror.Canonical.Name, selected.State, secret, workspace); err != nil {
		return err
	}
	candidates, err := discoverRecoveryCandidates(ctx, client, selected.CommitID)
	if err != nil {
		return err
	}
	eligible := candidates[:0]
	for _, candidate := range candidates {
		if candidate.RepositoryUUID != selected.State.Format.RepositoryUUID {
			continue
		}
		if pending != nil && candidate.TipCommit == pending.LocalCommit && (pending.Metadata == nil || candidate.Representation.Hash != pending.Metadata.ManifestHash || candidate.Representation.ObjectID != pending.Metadata.ManifestObjectID) {
			continue
		}
		eligible = append(eligible, candidate)
	}
	verified, _, err := verifyRecoveryCandidates(ctx, client, eligible, selected.CommitID, secret, workspace, run.options.SpaceReserveBytes, false)
	if err != nil {
		return err
	}
	if len(verified) != 1 || verified[0].Tip != selected.CommitID {
		return fmt.Errorf("full verification could not reconstruct exact metadata tip %s", selected.CommitID)
	}
	return nil
}

func (run *runtime) verifyFullPacks(ctx context.Context, client objectstore.Store, name string, state repository.State, secret *libsodium.Keyring, workspace string) error {
	raw := filepath.Join(workspace, "objects.raw")
	file, err := os.OpenFile(raw, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	walkErr := state.WalkObjects(format.DefaultLimits(), func(object format.ObjectEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := fmt.Fprintf(file, "%s\t%s\t%d\n", object.PackHash, object.PlaintextHash, object.PlaintextSize)
		return err
	})
	if err := errors.Join(walkErr, file.Close()); err != nil {
		return err
	}
	sorted := filepath.Join(workspace, "objects.sorted")
	if err := extsort.SortFiles(workspace, []string{raw}, sorted, extsort.Options{}); err != nil {
		return err
	}
	rows, err := openRestoreRows(sorted, 3)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	next := rows.Next()
	parts, err := os.OpenFile(filepath.Join(workspace, "parts.tsv"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = parts.Close() }()
	var size uint64
	err = state.WalkPacks(format.DefaultLimits(), func(part format.PackEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if part.PartSize > uint64(^uint64(0)>>1)-1-size {
			return fmt.Errorf("full verification pack size overflows")
		}
		size += part.PartSize
		if _, err := fmt.Fprintf(parts, "%s\t%d\t%d\t%s\t%s\t%s\t%d\t%s\n", part.PackHash, part.PartNumber, part.PartCount, part.PartHash, part.PartSHA256, part.PartMD5, part.PartSize, part.ObjectID); err != nil {
			return err
		}
		if part.PartNumber+1 != part.PartCount {
			return nil
		}
		var members map[string]uint64
		var err error
		members, next, err = loadRestorePackMembers(rows, next, part.PackHash)
		if err != nil {
			return err
		}
		if _, err := parts.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := run.verifyFullPack(ctx, client, name, parts, part.PackHash, size, secret, members); err != nil {
			return fmt.Errorf("full verification pack %s: %w", part.PackHash, err)
		}
		size = 0
		if err := parts.Truncate(0); err != nil {
			return err
		}
		_, err = parts.Seek(0, io.SeekStart)
		return err
	})
	if err != nil {
		return err
	}
	if next || size != 0 {
		return fmt.Errorf("full verification catalog did not finish")
	}
	return rows.Err()
}

func (run *runtime) verifyFullPack(ctx context.Context, client objectstore.Store, name string, parts io.Reader, hash string, size uint64, secret *libsodium.Keyring, members map[string]uint64) error {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := format.WalkPacks(parts, format.DefaultLimits(), func(part format.PackEntry) error {
			key, err := format.ObjectKey(part.PartHash, part.ObjectID)
			if err != nil {
				return err
			}
			expected := objectstore.Object{Size: part.PartSize, BLAKE2b: part.PartHash, SHA256: part.PartSHA256, MD5: part.PartMD5}
			err = client.GetVerified(ctx, key, expected, writer)
			if err != nil {
				return errors.Join(err, run.observeDataFailure(name, key, err))
			}
			return nil
		})
		_ = writer.CloseWithError(err)
		done <- err
	}()
	err := pack.DecryptAndRead(reader, hash, size, secret, members, func(_ string, _ uint64, plain io.Reader) error { _, err := io.Copy(io.Discard, plain); return err })
	_ = reader.CloseWithError(err)
	return errors.Join(err, <-done)
}
