package s3server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"backup/internal/format"
	"backup/internal/objectstore"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/sys/unix"
)

func TestChecksumAuditRequiresPublicationBarrier(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-put-barrier", true: "pending-put-barrier"}[pending], func(t *testing.T) {
			t.Setenv("AWS_MAX_ATTEMPTS", "1")
			root := t.TempDir()
			body := []byte("readable bytes are not a durable acknowledgement")
			key := objectKey(body, 17)
			objectPath := filepath.Join(root, filepath.FromSlash(key))
			server, err := Open(Config{
				Root: root, Bucket: testBucket, Region: testRegion,
				Credential: Credential{AccessKey: accessKey, SecretKey: secretKey},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			var failed atomic.Bool
			failed.Store(true)
			var barriers atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			server.syncObjectParent = func(fd int) error {
				call := barriers.Add(1)
				var stat unix.Stat_t
				if err := unix.Fstat(fd, &stat); err != nil {
					return err
				}
				var expected unix.Stat_t
				if err := unix.Stat(filepath.Dir(objectPath), &expected); err != nil {
					return err
				}
				if stat.Dev != expected.Dev || stat.Ino != expected.Ino {
					t.Error("barrier used something other than the object's containing directory")
					return fmt.Errorf("wrong publication directory")
				}
				if pending && call == 1 {
					close(entered)
					<-release
				}
				if failed.Load() {
					return unix.EIO
				}
				return unix.Fsync(fd)
			}
			httpServer := httptest.NewTLSServer(server)
			t.Cleanup(httpServer.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := objectstore.New(ctx, objectstore.Options{
				Mirror:              format.Mirror{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://" + testBucket, Endpoint: httpServer.URL, Region: testRegion},
				CredentialsProvider: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
				HTTPClient:          httpServer.Client(),
			})
			if err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(t.TempDir(), "payload")
			if err := os.WriteFile(staged, body, 0o600); err != nil {
				t.Fatal(err)
			}
			expected := objectstore.HashBytes(body)
			created := make(chan objectstore.CreateResult, 1)
			go func() { created <- client.PutFile(ctx, key, staged, expected) }()
			if pending {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("PUT did not reach the post-link barrier")
				}
			} else if result := <-created; result.Disposition != objectstore.CreateAmbiguous {
				t.Fatalf("failed post-link barrier: %+v", result)
			}
			var downloaded bytes.Buffer
			beforeGet := barriers.Load()
			if err := client.GetVerified(ctx, key, expected, &downloaded); err != nil || !bytes.Equal(downloaded.Bytes(), body) {
				t.Fatalf("published object not readable: %q %v", downloaded.Bytes(), err)
			}
			h := &harness{t: t, http: httpServer, client: httpServer.Client(), now: time.Now()}
			response := h.do(h.request(http.MethodHead, key, nil))
			closeBody(t, response)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("ordinary HEAD failed: %d", response.StatusCode)
			}
			if barriers.Load() != beforeGet {
				t.Fatal("ordinary GET/HEAD unexpectedly established a publication barrier")
			}
			if err := client.Audit(ctx, key, expected); err == nil {
				t.Error("checksum audit acknowledged bytes while publication fsync was failing")
			} else if errors.Is(err, objectstore.ErrCorrupt) || errors.Is(err, objectstore.ErrMissing) {
				t.Errorf("barrier failure was classified as content loss: %v", err)
			}
			failed.Store(false)
			beforeAudit := barriers.Load()
			if err := client.Audit(ctx, key, expected); err != nil {
				t.Fatalf("audit after successful publication barrier: %v", err)
			}
			if barriers.Load() <= beforeAudit {
				t.Error("successful audit did not establish its own publication barrier")
			}
			if pending {
				select {
				case result := <-created:
					t.Fatalf("original PUT completed before its barrier was released: %+v", result)
				default:
				}
				unblock()
				if result := <-created; result.Disposition != objectstore.CreateAcknowledged {
					t.Fatalf("original PUT after barrier release: %+v", result)
				}
			}
			if data, err := os.ReadFile(objectPath); err != nil || !bytes.Equal(data, body) {
				t.Fatalf("audit changed the immutable object: %q %v", data, err)
			}
		})
	}
}
