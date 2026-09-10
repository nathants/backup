package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"backup/internal/format"
	"golang.org/x/crypto/blake2b"
)

func TestFindReadsAcceptedTipDuringPendingPublication(t *testing.T) {
	for _, checkpoint := range []string{"local-commit-accepted", "git-push-intent-recorded", "git-push-confirmed"} {
		t.Run(checkpoint, func(t *testing.T) {
			h := newIntegrationHarness(t)
			h.options.PackTarget, h.options.PartSize, h.options.MetadataPartSize = 1<<20, 1<<20, 1<<20
			ctx := context.Background()
			genesis, err := initializePublished(ctx, h.options, h.publicKey)
			if err != nil {
				t.Fatal(err)
			}
			assertFind := func(revision, wantCommit string, want []format.IndexEntry) {
				t.Helper()
				var rows []format.IndexEntry
				var resolved string
				resolutions := 0
				count, err := Find(h.options, `^\./payload$`, revision, func(commit string) error {
					resolved = commit
					resolutions++
					return nil
				}, func(row format.IndexEntry) error {
					rows = append(rows, row)
					return nil
				})
				if err != nil || resolutions != 1 || resolved != wantCommit || count != uint64(len(want)) || !slices.Equal(rows, want) {
					t.Fatalf("find %s: resolved=%s (%d times) count=%d rows=%#v err=%v; want %s %#v", revision, resolved, resolutions, count, rows, err, wantCommit, want)
				}
			}
			assertFind("HEAD", genesis.CommitID, nil)

			payload := []byte("pending snapshot payload")
			path := filepath.Join(h.root, "payload")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			want := []format.IndexEntry{{
				Path: "./payload", Kind: format.KindFile, Ref: fmt.Sprintf("blake2b:%x", blake2b.Sum512(payload)),
				Size: uint64(len(payload)), Mode: 0o600, MtimeNS: info.ModTime().UnixNano(),
			}}
			if _, err := Add(ctx, h.options, false); err != nil {
				t.Fatal(err)
			}
			interrupted := h.options
			stop := errors.New("interrupted publication")
			interrupted.failurePoint = func(point string) error {
				if point == checkpoint {
					return stop
				}
				return nil
			}
			if _, err := Commit(ctx, interrupted); !errors.Is(err, stop) {
				t.Fatalf("checkpoint %s: %v", checkpoint, err)
			}
			pending := loadTestTransaction(t, h.options)
			if !pending.LocalAccepted || pending.LocalCommit == genesis.CommitID || pending.PushAttempted != (checkpoint != "local-commit-accepted") || pending.PushConfirmed != (checkpoint == "git-push-confirmed") {
				t.Fatal("fixture did not retain the intended pending publication state")
			}
			txnPath := filepath.Join(h.options.statePath(), transactionFilename)
			beforeTransaction, err := os.ReadFile(txnPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeMetadata := snapshotTestMetadata(t, h.options.repositoryPath())

			assertFind("HEAD", pending.LocalCommit, want)
			assertFind(pending.LocalCommit, pending.LocalCommit, want)
			assertFind(genesis.CommitID, genesis.CommitID, nil)
			// A pending accepted tip remains inspectable even when the primary
			// cannot answer; reading must not attempt publication or a fetch.
			if err := os.Rename(h.bare, h.bare+"-offline"); err != nil {
				t.Fatal(err)
			}
			assertFind("HEAD", pending.LocalCommit, want)
			if err := os.Rename(h.bare+"-offline", h.bare); err != nil {
				t.Fatal(err)
			}

			// An independently advanced primary must not be materialized over
			// the pending transaction, even though its commit object is local.
			_, remote := advanceTestMetadataRemote(t, h)
			assertFind("HEAD", pending.LocalCommit, want)
			resolved := false
			visited := false
			count, err := Find(h.options, ".", remote, func(string) error {
				resolved = true
				return nil
			}, func(format.IndexEntry) error {
				visited = true
				return nil
			})
			if err == nil || resolved || visited || count != 0 {
				t.Fatalf("find accepted a revision outside the local validated history: count=%d resolved=%t visited=%t err=%v", count, resolved, visited, err)
			}
			if head := strings.TrimSpace(runGit(t, "-C", h.options.repositoryPath(), "rev-parse", "HEAD")); head != pending.LocalCommit {
				t.Fatalf("find advanced local head to %s", head)
			}
			if after, err := os.ReadFile(txnPath); err != nil || !bytes.Equal(after, beforeTransaction) {
				t.Fatalf("find changed the pending transaction: %v", err)
			}
			if after := snapshotTestMetadata(t, h.options.repositoryPath()); !maps.Equal(after, beforeMetadata) {
				t.Fatal("find changed the pending metadata worktree")
			}
		})
	}
}
