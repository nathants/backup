package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"

	"github.com/nathants/go-libsodium"
)

func TestEmptyRecipientsPermitLocalPlanningButNeverPublication(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	options := h.options
	options.ClientFactory = func(context.Context, localconfig.Mirror) (objectstore.Store, error) {
		t.Fatal("network client constructed with empty recipients")
		return nil, nil
	}
	if _, err := Init(ctx, options); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(h.root, ".backup", ".publickeys"))
	if err != nil || len(data) != 0 {
		t.Fatal("init did not create an empty recipient file")
	}
	if _, err := Add(ctx, options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffCandidate(options, func(Diff) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, options); err == nil || !strings.Contains(err.Error(), "recipient list is empty") {
		t.Fatalf("empty commit: %v", err)
	}
	if refs := strings.TrimSpace(runGit(t, "--git-dir", h.bare, "for-each-ref", "--format=%(objectname)")); refs != "" {
		t.Fatal("published empty-recipient genesis")
	}
	if err := Reset(options); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, options, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, ".backup", ".publickeys"), []byte(fmt.Sprintf("%x\n", h.publicKey)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err == nil || !strings.Contains(err.Error(), "changed after add") {
		t.Fatalf("recipient edit skipped re-add: %v", err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
}

func TestRotatedKeysRestoreAndRecoverMixedGenerations(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	if _, err := initializePublished(ctx, h.options, h.publicKey); err != nil {
		t.Fatal(err)
	}
	snapshot := func(name, value string) SnapshotResult {
		t.Helper()
		if err := os.WriteFile(filepath.Join(h.root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, h.options, false); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, h.options)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := snapshot("old", "old generation")
	pub, sec, err := libsodium.RotateKeyChain(libsodium.KeyChains{{h.publicKey}}, libsodium.KeyChains{{h.secretKey}})
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	secretText, err := sec.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, ".backup", ".publickeys"), publicText, 0644); err != nil {
		t.Fatal(err)
	}
	latest := snapshot("new", "new generation")
	if _, err := Verify(ctx, h.options, 1, latest.CommitID); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_FILE", "")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_CMD", "")
	// Either incomplete historical key set must fail before publishing any path.
	for _, key := range sec[0] {
		t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", key))
		target := t.TempDir()
		result, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./(old|new)$`, Revision: latest.CommitID, TargetRoot: target})
		if err == nil || result.Published != 0 {
			t.Fatalf("incomplete key set: %+v %v", result, err)
		}
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			t.Fatal("failed decryption changed destination")
		}
	}
	// A standalone retained secret can still read its historical snapshot.
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", h.secretKey))
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./old$`, Revision: first.CommitID, TargetRoot: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	// The on-demand source is invoked once, not once for each encrypted pack.
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	secretFile := filepath.Join(dir, "secret")
	count := filepath.Join(dir, "count")
	if err := os.WriteFile(secretFile, secretText, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(fmt.Sprintf("#!/bin/sh\nprintf 'called\\n' >> '%s'\ncat '%s'\n", count, secretFile)), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", "")
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY_CMD", source)
	target := t.TempDir()
	if _, err := Restore(ctx, h.options, RestoreRequest{Pattern: `^\./(old|new)$`, Revision: latest.CommitID, TargetRoot: target}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"old": "old generation", "new": "new generation"} {
		data, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || string(data) != want {
			t.Fatalf("restored %s: %v", name, err)
		}
	}
	calls, err := os.ReadFile(count)
	if err != nil || !bytes.Equal(calls, []byte("called\n")) {
		t.Fatalf("secret source was not reused: %v", err)
	}
	// All bundle generations remain recoverable without the primary Git service.
	if err := os.Rename(h.bare, h.bare+".unavailable"); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "recovered.git")
	recovered, err := Recover(ctx, h.options, RecoverRequest{Mirror: "local", Tip: latest.CommitID, Destination: destination})
	if err != nil || recovered.RecoveredTip != latest.CommitID {
		t.Fatalf("mixed-generation recovery: %+v %v", recovered, err)
	}
}

func TestHistoricalMetadataRepairUsesTodaysRecipients(t *testing.T) {
	h := newIntegrationHarness(t)
	ctx := context.Background()
	genesis, err := initializePublished(ctx, h.options, h.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, sec, err := libsodium.RotateKeyChain(libsodium.KeyChains{{h.publicKey}}, libsodium.KeyChains{{h.secretKey}})
	if err != nil {
		t.Fatal(err)
	}
	text, err := pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, ".backup", ".publickeys"), text, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, h.options, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(ctx, h.options); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_REMOTE_AWS_SECRETKEY", fmt.Sprintf("%x", sec[0][1]))
	repaired, err := RepairMetadataEdge(ctx, h.options, "local", genesis.CommitID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := format.MetadataManifestKey(genesis.CommitID, repaired.ManifestHash, repaired.ManifestObjectID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(h.serverRoot, key))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := format.ParseMetadataManifest(bytes.NewReader(data), format.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var cipher bytes.Buffer
	for _, part := range manifest.Parts {
		key, err := format.MetadataPartKey(part)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(h.serverRoot, key))
		if err != nil {
			t.Fatal(err)
		}
		cipher.Write(data)
	}
	oldRing, err := libsodium.NewKeyring([][]byte{h.secretKey})
	if err != nil {
		t.Fatal(err)
	}
	newRing, err := libsodium.NewKeyring([][]byte{sec[0][1]})
	if err != nil {
		t.Fatal(err)
	}
	if err := oldRing.Decrypt(bytes.NewReader(cipher.Bytes()), io.Discard); err == nil {
		t.Fatal("historical repair encrypted to superseded key")
	}
	if err := newRing.Decrypt(bytes.NewReader(cipher.Bytes()), io.Discard); err != nil {
		t.Fatal(err)
	}
}
