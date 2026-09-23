package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"backup/internal/format"
	"golang.org/x/sys/unix"
)

func filesystemFixture(t *testing.T) (*Filesystem, string, string) {
	t.Helper()
	directory := t.TempDir()
	identity, err := InitializeFilesystem(directory, "-")
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenFilesystem(directory, "-", identity, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, directory, identity
}
func filesystemSource(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func filesystemKey(t *testing.T, object Object) string {
	t.Helper()
	key, err := format.ObjectKey(object.BLAKE2b, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestFilesystemStoreRoundTripAndImmutableConflict(t *testing.T) {
	store, directory, identity := filesystemFixture(t)
	data := []byte("encrypted object bytes")
	object := HashBytes(data)
	key := filesystemKey(t, object)
	source := filesystemSource(t, data)
	ctx := context.Background()
	if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateAcknowledged || result.Err != nil {
		t.Fatalf("create: %+v", result)
	}
	if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateConflict {
		t.Fatalf("retry: %+v", result)
	}
	if err := store.Audit(ctx, key, object); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := store.GetVerified(ctx, key, object, &output); err != nil || !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("read: %q %v", output.Bytes(), err)
	}
	if result := store.PutFile(ctx, key, filesystemSource(t, []byte("wrong")), HashBytes([]byte("wrong"))); result.Disposition != CreateFailed {
		t.Fatalf("key substitution: %+v", result)
	}
	for i := 0; i < 2; i++ {
		keys, err := store.List(ctx, "objects/")
		if err != nil || len(keys) != 1 || keys[0] != key {
			t.Fatalf("list: %v %v", keys, err)
		}
	}
	if duplicate, err := OpenFilesystem(directory, "-", identity, 1); err == nil {
		_ = duplicate.Close()
		t.Fatal("parallel opener accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFilesystem(directory, "-", identity, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if err := reopened.Audit(ctx, key, object); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(filepath.Join(directory, key))
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("object mode: %v %v", stat, err)
	}
}

func TestFilesystemCorruptionMissingAndUnavailable(t *testing.T) {
	store, directory, _ := filesystemFixture(t)
	ctx := context.Background()
	object := HashBytes([]byte("ciphertext"))
	key := filesystemKey(t, object)
	if result := store.PutFile(ctx, key, filesystemSource(t, []byte("ciphertext")), object); result.Err != nil {
		t.Fatal(result.Err)
	}
	if err := os.WriteFile(filepath.Join(directory, key), []byte("corruption"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Audit(ctx, key, object); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption not classified: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, key)); err != nil {
		t.Fatal(err)
	}
	if err := store.Audit(ctx, key, object); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing not classified: %v", err)
	}
	moved := directory + "-disconnected"
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(moved, directory); err != nil {
			t.Error(err)
		}
	}()
	if err := store.Audit(ctx, key, object); err == nil || errors.Is(err, ErrMissing) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("absent disk classified as corruption/loss: %v", err)
	}
	if result := store.PutFile(ctx, key, filesystemSource(t, []byte("ciphertext")), object); result.Disposition != CreateFailed {
		t.Fatalf("write to disconnected store: %+v", result)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("absent path was created: %v", err)
	}
}

func TestFilesystemInitializationIdentityAndMountChecks(t *testing.T) {
	directory := t.TempDir()
	if _, err := InitializeFilesystem(directory, directory); err == nil {
		t.Fatal("ordinary directory accepted as a mount")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed mount preflight wrote state: %v %v", entries, err)
	}
	identity, err := InitializeFilesystem(directory, "-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeFilesystem(directory, "-"); err == nil {
		t.Fatal("nonempty store reinitialized")
	}
	for _, test := range []struct{ directory, mount, identity string }{
		{directory, "-", "filesystem://" + strings.Repeat("0", 32)},
		{directory, directory, identity},
		{directory, t.TempDir(), identity},
		{filepath.Join(t.TempDir(), "missing"), "-", identity},
	} {
		if store, err := OpenFilesystem(test.directory, test.mount, test.identity, 1); err == nil {
			_ = store.Close()
			t.Fatalf("invalid binding accepted: %+v", test)
		}
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenFilesystem(link, "-", identity, 1); err == nil {
		_ = store.Close()
		t.Fatal("symlink root accepted")
	}
	if err := os.Remove(filepath.Join(directory, filesystemMarker)); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(directory, filesystemMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenFilesystem(directory, "-", identity, 1); err == nil {
		_ = store.Close()
		t.Fatal("FIFO marker accepted")
	}
}

func TestFilesystemNoFollowAndInvalidKeys(t *testing.T) {
	store, directory, _ := filesystemFixture(t)
	ctx := context.Background()
	object := HashBytes([]byte("data"))
	key := filesystemKey(t, object)
	source := filesystemSource(t, []byte("data"))
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, "objects")); err != nil {
		t.Fatal(err)
	}
	if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateFailed {
		t.Fatalf("symlink parent accepted: %+v", result)
	}
	if err := store.GetVerified(ctx, key, object, io.Discard); err == nil {
		t.Fatal("symlink read accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("escaped destination: %v %v", entries, err)
	}
	for _, key := range []string{"../outside", "objects/../escape", "/absolute", "objects/" + object.BLAKE2b + "/bad", "metadata/manifests/" + strings.Repeat("x", 64) + "/" + object.BLAKE2b + "/" + strings.Repeat("a", 32)} {
		if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateFailed {
			t.Fatalf("invalid key accepted: %s", key)
		}
	}
	if err := os.Remove(filepath.Join(directory, "objects")); err != nil {
		t.Fatal(err)
	}
	if result := store.PutFile(ctx, key, source, object); result.Err != nil {
		t.Fatal(result.Err)
	}
	if err := os.Remove(filepath.Join(directory, key)); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(directory, key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.GetVerified(ctx, key, object, io.Discard); err == nil {
		t.Fatal("FIFO object accepted")
	}
}

func TestFilesystemPublicationFailureAndRetry(t *testing.T) {
	for _, point := range []string{"written", "file-synced", "parents-synced", "published", "directory-synced"} {
		t.Run(point, func(t *testing.T) {
			store, directory, identity := filesystemFixture(t)
			ctx := context.Background()
			data := []byte("complete ciphertext")
			object := HashBytes(data)
			key := filesystemKey(t, object)
			source := filesystemSource(t, data)
			injected := errors.New("injected durability failure")
			store.failurePoint = func(at string) error {
				if at == point {
					return injected
				}
				return nil
			}
			result := store.PutFile(ctx, key, source, object)
			if result.Disposition == CreateAcknowledged || !errors.Is(result.Err, injected) {
				t.Fatalf("failure acknowledged: %+v", result)
			}
			contents, err := os.ReadFile(filepath.Join(directory, key))
			published := point == "published" || point == "directory-synced"
			if published && (err != nil || !bytes.Equal(contents, data)) || !published && !os.IsNotExist(err) {
				t.Fatalf("partial/wrong publication: %q %v", contents, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenFilesystem(directory, "-", identity, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			result = reopened.PutFile(ctx, key, source, object)
			if published && result.Disposition != CreateConflict || !published && result.Disposition != CreateAcknowledged {
				t.Fatalf("retry: %+v", result)
			}
			if err := reopened.Audit(ctx, key, object); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFilesystemConcurrentCreatesAndStaleTemps(t *testing.T) {
	store, directory, _ := filesystemFixture(t)
	ctx := context.Background()
	object := HashBytes([]byte("data"))
	key := filesystemKey(t, object)
	source := filesystemSource(t, []byte("data"))
	stale := filesystemTempPrefix + strings.Repeat("b", 32)
	if err := os.WriteFile(filepath.Join(directory, stale), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan CreateResult, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- store.PutFile(ctx, key, source, object) }()
	}
	wg.Wait()
	close(results)
	created := 0
	for result := range results {
		switch result.Disposition {
		case CreateAcknowledged:
			created++
		case CreateConflict:
		default:
			t.Fatalf("create: %+v", result)
		}
	}
	if created != 1 {
		t.Fatalf("created %d times", created)
	}
	if _, err := os.Stat(filepath.Join(directory, stale)); !os.IsNotExist(err) {
		t.Fatalf("stale temp retained: %v", err)
	}
}

func TestFilesystemManifestListingAndBounds(t *testing.T) {
	store, _, _ := filesystemFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		data := []byte(fmt.Sprintf("manifest %d", i))
		object := HashBytes(data)
		key, err := format.MetadataManifestKey(strings.Repeat(fmt.Sprint(i), 64), object.BLAKE2b, strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		if result := store.PutFile(ctx, key, filesystemSource(t, data), object); result.Err != nil {
			t.Fatal(result.Err)
		}
		if got, err := store.GetManifest(ctx, key, object.BLAKE2b); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("manifest: %q %v", got, err)
		}
	}
	if _, err := store.ListLimited(ctx, "metadata/manifests/", 1); err == nil {
		t.Fatal("listing limit ignored")
	}
	if keys, err := store.ListLimited(ctx, "metadata/manifests/"+strings.Repeat("0", 64)+"/", 1); err != nil || len(keys) != 1 {
		t.Fatalf("anchored listing: %v %v", keys, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.List(canceled, "objects/"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestFilesystemReserveDoesNotPreventAuditingExistingCreate(t *testing.T) {
	store, _, _ := filesystemFixture(t)
	ctx := context.Background()
	object := HashBytes([]byte("data"))
	key := filesystemKey(t, object)
	source := filesystemSource(t, []byte("data"))
	if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateAcknowledged {
		t.Fatalf("create: %+v", result)
	}
	store.reserveBytes = ^uint64(0)
	if result := store.PutFile(ctx, key, source, object); result.Disposition != CreateConflict {
		t.Fatalf("existing key retry requires extra free space: %+v", result)
	}
	if err := store.Audit(ctx, key, object); err != nil {
		t.Fatal(err)
	}
	other := strings.TrimSuffix(key, strings.Repeat("a", 32)) + strings.Repeat("b", 32)
	if result := store.PutFile(ctx, other, source, object); result.Disposition != CreateFailed || !strings.Contains(result.Err.Error(), "reserve") {
		t.Fatalf("new key ignored reserve: %+v", result)
	}
}

func TestFilesystemRejectsBadCopiedBytesWithoutPublication(t *testing.T) {
	store, directory, _ := filesystemFixture(t)
	ctx := context.Background()
	expected := HashBytes([]byte("good"))
	key := filesystemKey(t, expected)
	for _, data := range [][]byte{[]byte("evil"), []byte("short"), nil} {
		result := store.PutFile(ctx, key, filesystemSource(t, data), expected)
		if result.Disposition != CreateFailed || result.Err == nil {
			t.Fatalf("bad source acknowledged: %+v", result)
		}
		if _, err := os.Lstat(filepath.Join(directory, key)); !os.IsNotExist(err) {
			t.Fatalf("bad source published: %v", err)
		}
	}
	if keys, err := store.List(ctx, "objects/"); err != nil || len(keys) != 0 {
		t.Fatalf("failed create became listable: %v %v", keys, err)
	}
}

func TestFilesystemRootReplacementDuringCreateStaysConfined(t *testing.T) {
	store, directory, identity := filesystemFixture(t)
	ctx := context.Background()
	moved := directory + "-opened"
	store.failurePoint = func(point string) error {
		if point != "written" {
			return nil
		}
		if err := os.Rename(directory, moved); err != nil {
			return err
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(directory, filesystemMarker), []byte("backup-filesystem-v1\n"+identity+"\n"), 0o600)
	}
	defer func() {
		if _, err := os.Stat(moved); err == nil {
			if err := os.Remove(filepath.Join(directory, filesystemMarker)); err != nil {
				t.Error(err)
			}
			if err := os.Remove(directory); err != nil {
				t.Error(err)
			}
			if err := os.Rename(moved, directory); err != nil {
				t.Error(err)
			}
		}
	}()
	expected := HashBytes([]byte("good"))
	key := filesystemKey(t, expected)
	result := store.PutFile(ctx, key, filesystemSource(t, []byte("good")), expected)
	if result.Disposition != CreateFailed || !strings.Contains(result.Err.Error(), "directory changed") {
		t.Fatalf("root replacement accepted: %+v", result)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != filesystemMarker {
		t.Fatalf("write escaped opened root: %v %v", entries, err)
	}
	if _, err := os.Lstat(filepath.Join(moved, key)); !os.IsNotExist(err) {
		t.Fatalf("changed root still acknowledged publication: %v", err)
	}
}
