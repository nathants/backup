package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"backup/internal/localconfig"
	"backup/internal/objectstore"
)

func TestHistoricalSyncRetainsNewerEvidenceAndAuditsSelectedRevision(t *testing.T) {
	ctx := context.Background()
	h, remote := newIntegrationHarness(t), newIntegrationHarness(t)
	config, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	config = append(config, fmt.Appendf(nil, "mirror\tremote\tbackup-server\ts3://backup-test/repository\t%s\tus-east-1\t-\t-\n", remote.http.URL)...)
	if err := os.WriteFile(h.configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	localFactory := h.options.ClientFactory
	h.options.ClientFactory = func(ctx context.Context, pin localconfig.Mirror) (objectstore.Store, error) {
		if pin.Canonical.Name == "remote" {
			return remote.options.ClientFactory(ctx, pin)
		}
		return localFactory(ctx, pin)
	}
	offline := h.options
	offline.ClientFactory = func(ctx context.Context, pin localconfig.Mirror) (objectstore.Store, error) {
		if pin.Canonical.Name == "remote" {
			return nil, fmt.Errorf("destination offline")
		}
		return localFactory(ctx, pin)
	}
	if _, err := initializePublished(ctx, offline, h.publicKey); err != nil {
		t.Fatal(err)
	}
	var revisions []string
	for _, content := range []string{"historical payload", "latest payload"} {
		if err := os.WriteFile(filepath.Join(h.root, "file"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Add(ctx, offline, false); err != nil {
			t.Fatal(err)
		}
		result, err := Commit(ctx, offline)
		if err != nil {
			t.Fatal(err)
		}
		revisions = append(revisions, result.CommitID)
	}
	synced, err := Sync(ctx, h.options, "local", "remote", revisions[0])
	if err != nil || synced.DataCopied == 0 || synced.MetadataCopied == 0 {
		t.Fatalf("catch up historical revision: %+v %v", synced, err)
	}
	again, err := Sync(ctx, h.options, "local", "remote", revisions[0])
	if err != nil || again.DataCopied != 0 || again.MetadataCopied != 0 {
		t.Fatalf("repeat historical sync: %+v %v", again, err)
	}
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	head, history, err := run.validatedHead(false)
	if err != nil {
		_ = run.close()
		t.Fatal(err)
	}
	defer func() { _ = history.Close() }()
	uuid := head.State.Format.RepositoryUUID
	ledger, err := run.loadLedger(uuid)
	if err != nil || ledger.Mirrors["local"] != revisions[1] || ledger.Mirrors["remote"] != revisions[0] {
		t.Fatalf("historical sync lost or regressed completion evidence: %+v %v", ledger, err)
	}
	selected, err := history.ResolveRevision(revisions[0])
	if err != nil {
		t.Fatal(err)
	}
	part := firstTestPackPart(t, selected.State)
	if err := run.close(); err != nil {
		t.Fatal(err)
	}

	// Newer ledger evidence must not skip the older revision's actual audit.
	path := filepath.Join(h.serverRoot, "objects", part.PartHash, part.ObjectID)
	healthy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, h.options, "local", "remote", revisions[0]); err == nil {
		t.Fatal("historical sync trusted newer ledger evidence instead of auditing its source")
	}
	if err := os.WriteFile(path, healthy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, h.options, "local", "remote", revisions[0]); err != nil {
		t.Fatal(err)
	}
	reopened, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.close() }()
	ledger, err = reopened.loadLedger(uuid)
	if err != nil || !ledger.Quarantined["local"] || ledger.Mirrors["local"] != "" || ledger.Mirrors["remote"] != revisions[0] {
		t.Fatalf("historical sync cleared a current quarantine: %+v %v", ledger, err)
	}
}
