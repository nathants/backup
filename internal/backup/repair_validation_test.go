package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Observe real staged-file I/O without adding counters to the validation code.
func watchFileOpens(t *testing.T, path string) func() bool {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	return func() bool {
		t.Helper()
		opened := false
		var buffer [4096]byte
		for {
			count, err := unix.Read(fd, buffer[:])
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				return opened
			}
			if err != nil || count == 0 {
				t.Fatalf("read staged-file notifications: %d %v", count, err)
			}
			opened = true
		}
	}
}

func TestRepairValidationReusesOnlyUnchangedInputs(t *testing.T) {
	h, _ := stageRepairFixture(t, 2)
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	var control transaction
	if err := run.store.Read(transactionFilename, &control); err != nil {
		t.Fatal(err)
	}
	watchRef := func(ref stagedFileRef) func() bool {
		return watchFileOpens(t, filepath.Join(h.options.transactionFilesPath(), ref.RelativePath))
	}
	descriptorOpened := watchRef(control.DataPartsFile)
	catalogOpened := watchRef(control.CandidateFiles["packs.tsv"])
	requireReads := func(want bool) {
		t.Helper()
		descriptors, catalog := descriptorOpened(), catalogOpened()
		if descriptors != want || catalog != want {
			t.Fatalf("repair validation reads: descriptors=%t catalog=%t, want both %t", descriptors, catalog, want)
		}
	}
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	requireReads(true)
	candidate, err := run.loadCandidateState(txn)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := run.loadLedger(candidate.Format.RepositoryUUID)
	if err != nil {
		t.Fatal(err)
	}
	var acknowledgements uint64
	run.options.failurePoint = func(point string) error {
		switch point {
		case "data-object-created-before-ack":
			// The upload walk itself must still read and verify the descriptors.
			if acknowledgements == 0 {
				if !descriptorOpened() {
					t.Fatal("upload did not verify its staged descriptors")
				}
			}
		case "data-object-acknowledged":
			acknowledgements++
			requireReads(false)
			if err := run.store.Read(transactionFilename, &control); err != nil {
				return err
			}
			if control.Mirrors["local"].DataPartCursor != acknowledgements {
				t.Fatal("acknowledgement was not saved to the durable control record")
			}
		}
		return nil
	}
	rotated, err := run.uploadDataParts(context.Background(), txn, ledger)
	if err != nil || rotated || acknowledgements != 2 {
		t.Fatalf("upload repair parts: acknowledgements=%d rotated=%t err=%v", acknowledgements, rotated, err)
	}
	requireReads(false)

	// Identical bytes under a different staged path are different inputs. Both
	// caches must copy their keys rather than alias the transaction's map.
	for _, catalog := range []bool{true, false} {
		ref, relative := txn.DataPartsFile, "candidate/rebound-descriptors"
		if catalog {
			ref, relative = txn.CandidateFiles["packs.tsv"], "candidate/rebound-packs"
		}
		data, err := run.readStagedRef(ref, int64(ref.Size))
		if err != nil {
			t.Fatal(err)
		}
		rebound, err := run.ensureStagedBytes(relative, data, stagedFileRef{})
		if err != nil {
			t.Fatal(err)
		}
		_ = descriptorOpened()
		_ = catalogOpened()
		if catalog {
			txn.CandidateFiles["packs.tsv"] = rebound
			catalogOpened = watchRef(rebound)
		} else {
			txn.DataPartsFile = rebound
			descriptorOpened = watchRef(rebound)
		}
		if err := run.saveTransaction(txn); err != nil {
			t.Fatal(err)
		}
		requireReads(true)
		if err := run.saveTransaction(txn); err != nil {
			t.Fatal(err)
		}
		requireReads(false)
	}

	for _, restart := range []bool{false, true} {
		if restart {
			if err := run.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openRuntime(h.options, true)
			if err != nil {
				t.Fatal(err)
			}
			run = reopened
		}
		if _, err := run.loadTransaction(); err != nil {
			t.Fatal(err)
		}
		requireReads(true)
	}
}

func TestRepairValidationRejectsChangedMetadataPaths(t *testing.T) {
	h, _ := stageRepairFixture(t, 1)
	stop := errors.New("metadata staged")
	interrupted := h.options
	interrupted.failurePoint = func(point string) error {
		if point == "metadata-staged" {
			return stop
		}
		return nil
	}
	if _, err := Commit(context.Background(), interrupted); !errors.Is(err, stop) {
		t.Fatalf("stage repair metadata: %v", err)
	}
	run, err := openRuntime(h.options, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.close() }()
	txn, err := run.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := txn.Metadata.ManifestRelativePath
	if err := run.walkDataParts(txn, func(_ uint64, part stagedDataPart) error {
		txn.Metadata.ManifestRelativePath = part.RelativePath
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(h.options.statePath(), transactionFilename)
	original, err := os.ReadFile(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := run.saveTransaction(txn); err == nil || !strings.Contains(err.Error(), "duplicate staged path") {
			t.Fatalf("metadata/data collision was accepted: %v", err)
		}
	}
	preserved, err := os.ReadFile(controlPath)
	if err != nil || string(preserved) != string(original) {
		t.Fatalf("invalid metadata path replaced usable control: %v", err)
	}
	txn.Metadata.ManifestRelativePath = manifestPath
	if err := run.saveTransaction(txn); err != nil {
		t.Fatalf("valid metadata paths could not be retried: %v", err)
	}
}
