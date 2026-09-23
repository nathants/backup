package objectstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backup/internal/format"
	"backup/internal/s3server"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/crypto/blake2b"
)

func TestClientAgainstProductionServerContract(t *testing.T) {
	server, err := s3server.Open(s3server.Config{
		Root: t.TempDir(), Bucket: "backup-test", Prefix: "repository", Region: "us-east-1",
		Credential: s3server.Credential{AccessKey: "backup", SecretKey: "backup-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	httpServer := httptest.NewTLSServer(server)
	defer httpServer.Close()
	mirror := format.Mirror{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: httpServer.URL, Region: "us-east-1"}
	client, err := New(context.Background(), Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider("backup", "backup-secret", ""), HTTPClient: httpServer.Client()})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("object store payload")
	expected := HashBytes(payload)
	key := "objects/" + expected.BLAKE2b + "/11111111111111111111111111111111"
	filename := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(filename, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	result := client.PutFile(context.Background(), key, filename, expected)
	if result.Disposition != CreateAcknowledged || result.Err != nil {
		t.Fatalf("first create: disposition=%v err=%+v", result.Disposition, result.Err)
	}
	result = client.PutFile(context.Background(), key, filename, expected)
	if result.Disposition != CreateConflict || result.Err == nil {
		t.Fatalf("second create: %#v", result)
	}
	if err := client.Audit(context.Background(), key, expected); err != nil {
		t.Fatal(err)
	}
	var downloaded bytes.Buffer
	if err := client.GetVerified(context.Background(), key, expected, &downloaded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatal("download mismatch")
	}
	keys, err := client.List(context.Background(), "objects/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("keys=%#v", keys)
	}
	if _, err := client.ListLimited(context.Background(), "objects/", 0); err == nil {
		t.Fatal("accepted a zero listing limit")
	}
	if _, err := client.ListLimited(context.Background(), "objects/", 1); err != nil {
		t.Fatalf("exact listing limit failed: %v", err)
	}
	secondPayload := []byte("second object store payload")
	secondExpected := HashBytes(secondPayload)
	secondKey := "objects/" + secondExpected.BLAKE2b + "/33333333333333333333333333333333"
	secondFile := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(secondFile, secondPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	if result := client.PutFile(context.Background(), secondKey, secondFile, secondExpected); result.Disposition != CreateAcknowledged {
		t.Fatalf("second object create: %#v", result)
	}
	if _, err := client.ListLimited(context.Background(), "objects/", 1); err == nil || !strings.Contains(err.Error(), "exceeds 1 keys") {
		t.Fatalf("bounded listing accepted excess objects: %v", err)
	}
	deeperKeys, err := client.List(context.Background(), "objects/"+expected.BLAKE2b+"/")
	if err != nil || len(deeperKeys) != 1 || deeperKeys[0] != key {
		t.Fatalf("deep prefix keys=%#v err=%v", deeperKeys, err)
	}

	manifest := []byte("bounded manifest\n")
	manifestHash := blake2b.Sum512(manifest)
	manifestHashText := hex.EncodeToString(manifestHash[:])
	manifestKey := "metadata/manifests/" + strings.Repeat("a", 64) + "/" + manifestHashText + "/22222222222222222222222222222222"
	manifestFile := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(manifestFile, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if result := client.PutFile(context.Background(), manifestKey, manifestFile, HashBytes(manifest)); result.Disposition != CreateAcknowledged {
		t.Fatalf("manifest create: %#v", result)
	}
	got, err := client.GetManifest(context.Background(), manifestKey, manifestHashText)
	if err != nil || !bytes.Equal(got, manifest) {
		t.Fatalf("manifest: %q %v", got, err)
	}
}

type endpointRejectHTTPClient struct {
	calls int
}

func (client *endpointRejectHTTPClient) Do(*http.Request) (*http.Response, error) {
	client.calls++
	return nil, context.Canceled
}

func TestPinnedEndpointRejectsAmbientSDKOverrides(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	newClient := func(mirror format.Mirror, httpClient *endpointRejectHTTPClient) (*Client, error) {
		return New(context.Background(), Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider("reader", "reader-secret", ""), HTTPClient: httpClient})
	}
	assertOptions := func(t *testing.T, client *Client, endpoint string) {
		t.Helper()
		options := client.client.Options()
		if endpoint == "-" && options.BaseEndpoint != nil {
			t.Fatalf("ambient endpoint accepted: %q", *options.BaseEndpoint)
		}
		if endpoint != "-" && (options.BaseEndpoint == nil || *options.BaseEndpoint != endpoint) {
			t.Fatalf("base endpoint = %v, want %q", options.BaseEndpoint, endpoint)
		}
		if options.EndpointOptions.UseFIPSEndpoint != aws.FIPSEndpointStateDisabled {
			t.Fatalf("ambient FIPS mode accepted: %v", options.EndpointOptions.UseFIPSEndpoint)
		}
		if options.EndpointOptions.UseDualStackEndpoint != aws.DualStackEndpointStateDisabled {
			t.Fatalf("ambient dual-stack mode accepted: %v", options.EndpointOptions.UseDualStackEndpoint)
		}
	}
	assertRejected := func(t *testing.T, mirror format.Mirror) {
		t.Helper()
		httpClient := &endpointRejectHTTPClient{}
		client, err := newClient(mirror, httpClient)
		if err == nil {
			t.Fatalf("ambient AWS SDK endpoint override accepted: %#v", client)
		}
		if !strings.Contains(err.Error(), "AWS SDK endpoint overrides are not allowed") {
			t.Fatalf("wrong rejection: %v", err)
		}
		if httpClient.calls != 0 {
			t.Fatalf("made %d HTTP requests before rejecting endpoint override", httpClient.calls)
		}
	}
	awsMirror := format.Mirror{Name: "aws", Kind: format.MirrorAWSS3, S3URL: "s3://backup-test/repository", Endpoint: "-", Region: "us-east-1"}
	t.Run("global environment endpoint", func(t *testing.T) {
		t.Setenv("AWS_ENDPOINT_URL", "https://ambient.example.invalid")
		assertRejected(t, awsMirror)
	})
	t.Run("service environment endpoint", func(t *testing.T) {
		t.Setenv("AWS_ENDPOINT_URL_STS", "https://ambient.example.invalid")
		assertRejected(t, awsMirror)
	})
	t.Run("shared config endpoint", func(t *testing.T) {
		config := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(config, []byte("[default]\nregion = us-east-1\nendpoint_url = https://shared.example.invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", config)
		assertRejected(t, awsMirror)
	})
	t.Run("shared config service endpoints", func(t *testing.T) {
		config := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(config, []byte("[default]\nregion = us-east-1\nservices = local\n[services local]\nsts =\n  endpoint_url = https://shared.example.invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", config)
		assertRejected(t, awsMirror)
	})
	t.Run("role profile rejected before credential HTTP", func(t *testing.T) {
		config := filepath.Join(t.TempDir(), "config")
		contents := "[profile role]\nregion = us-east-1\nrole_arn = arn:aws:iam::123456789012:role/test\nsource_profile = source\nendpoint_url = https://shared.example.invalid\n[profile source]\naws_access_key_id = source\naws_secret_access_key = source-secret\n"
		if err := os.WriteFile(config, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", config)
		httpClient := &endpointRejectHTTPClient{}
		client, err := New(context.Background(), Options{Mirror: awsMirror, Profile: "role", HTTPClient: httpClient})
		if err == nil {
			t.Fatalf("role profile endpoint override accepted: %#v", client)
		}
		if !strings.Contains(err.Error(), "AWS SDK endpoint overrides are not allowed") {
			t.Fatalf("wrong rejection: %v", err)
		}
		if httpClient.calls != 0 {
			t.Fatalf("made %d credential HTTP requests before rejecting endpoint override", httpClient.calls)
		}
	})
	t.Run("environment endpoint modes are forced off", func(t *testing.T) {
		t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
		t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")
		client, err := newClient(awsMirror, &endpointRejectHTTPClient{})
		if err != nil {
			t.Fatal(err)
		}
		assertOptions(t, client, "-")
	})
	t.Run("shared config endpoint modes are forced off", func(t *testing.T) {
		config := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(config, []byte("[default]\nregion = us-east-1\nuse_fips_endpoint = true\nuse_dualstack_endpoint = true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_CONFIG_FILE", config)
		client, err := newClient(awsMirror, &endpointRejectHTTPClient{})
		if err != nil {
			t.Fatal(err)
		}
		assertOptions(t, client, "-")
	})
	t.Run("custom endpoint", func(t *testing.T) {
		t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
		t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")
		mirror := format.Mirror{Name: "server", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: "https://pinned.example.test", Region: "us-east-1"}
		client, err := newClient(mirror, &endpointRejectHTTPClient{})
		if err != nil {
			t.Fatal(err)
		}
		assertOptions(t, client, mirror.Endpoint)
	})
}

func TestTrustedHTTPClientBoundsHeaderAndBodyInactivity(t *testing.T) {
	t.Run("response headers", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			time.Sleep(100 * time.Millisecond)
		}))
		defer server.Close()
		client, err := trustedHTTPClientWithTimeouts("", 20*time.Millisecond, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Get(server.URL)
		if response != nil {
			defer func() { _ = response.Body.Close() }()
		}
		if err == nil {
			t.Fatal("stalled response headers did not time out")
		}
	})
	t.Run("body inactivity", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, "prefix")
			writer.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
			_, _ = io.WriteString(writer, "suffix")
		}))
		defer server.Close()
		client, err := trustedHTTPClientWithTimeouts("", time.Second, 20*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr == nil {
			t.Fatal("stalled response body did not time out")
		}
	})
}

func TestObjectIdentityAndKeyValidation(t *testing.T) {
	payload := []byte("identity payload")
	identity, err := HashReader(bytes.NewReader(payload))
	if err != nil || identity != HashBytes(payload) {
		t.Fatalf("streaming identity=%#v err=%v", identity, err)
	}
	if err := VerifyBytes(payload, identity); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBytes(append([]byte(nil), payload[:len(payload)-1]...), identity); err == nil {
		t.Fatal("changed bytes matched the expected object identity")
	}
	if _, err := HashReader(nil); err == nil {
		t.Fatal("nil object reader accepted")
	}
	client := &Client{prefix: "repository"}
	for _, key := range []string{"", "/absolute", "../escape", "..", "a/../b", "a//b", "a\x00b", "a\nb"} {
		if _, err := client.key(key); err == nil {
			t.Fatalf("unsafe logical key %q accepted", key)
		}
		if _, err := client.listPrefix(key); err == nil {
			t.Fatalf("unsafe logical prefix %q accepted", key)
		}
	}
	if key, err := client.key("objects/hash/id"); err != nil || key != "repository/objects/hash/id" {
		t.Fatalf("valid logical key=%q err=%v", key, err)
	}
}

func FuzzObjectIdentityAndLogicalKeys(f *testing.F) {
	f.Add([]byte("payload"), "objects/hash/id")
	f.Add([]byte{}, "../escape")
	f.Add([]byte("payload"), "objects/"+HashBytes([]byte("payload")).BLAKE2b+"/"+strings.Repeat("a", 32))
	f.Fuzz(func(t *testing.T, data []byte, key string) {
		if len(data)+len(key) > 1<<20 {
			t.Skip()
		}
		identity := HashBytes(data)
		if err := VerifyBytes(data, identity); err != nil {
			t.Fatalf("self identity rejected: %v", err)
		}
		client := &Client{prefix: "repository"}
		_, _ = client.key(key)
		_, _ = client.listPrefix(key)
		_, _ = filesystemKeyHash(key)
	})
}

func TestCloudflareR2UsesOnlyItsSupportedSHA256Checksum(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.Header.Get("If-None-Match") != "*" || request.Header.Get("X-Amz-Checksum-Sha256") == "" {
			http.Error(writer, "missing required create headers", http.StatusBadRequest)
			return
		}
		if request.Header.Get("Content-MD5") != "" {
			writer.Header().Set("Content-Type", "application/xml")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, "<Error><Code>InvalidRequest</Code><Message>You can only specify one non-default checksum at a time.</Message></Error>")
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	endpoint := httptest.NewTLSServer(handler)
	defer endpoint.Close()
	mirror := format.Mirror{Name: "r2", Kind: format.MirrorCloudflareR2, S3URL: "s3://backup-test/repository", Endpoint: endpoint.URL, Region: "auto"}
	client, err := New(context.Background(), Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider("writer", "secret", ""), HTTPClient: endpoint.Client()})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("r2 checksum contract")
	filename := filepath.Join(t.TempDir(), "part")
	if err := os.WriteFile(filename, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	key := "objects/" + HashBytes(payload).BLAKE2b + "/11111111111111111111111111111111"
	if result := client.PutFile(context.Background(), key, filename, HashBytes(payload)); result.Disposition != CreateAcknowledged {
		t.Fatalf("R2-compatible create failed: disposition=%v err=%v", result.Disposition, result.Err)
	}
}

func TestTrustedCAFileMustBeBoundedRegularNoFollowAndNotWritableByOthers(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(certificate, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHTTPClient(certificate); err == nil || !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("expected certificate parse error, got %v", err)
	}
	link := filepath.Join(directory, "ca-link.pem")
	if err := os.Symlink(certificate, link); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHTTPClient(link); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlinked CA file was accepted: %v", err)
	}
	if err := os.Chmod(certificate, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedHTTPClient(certificate); err == nil || !strings.Contains(err.Error(), "group/other") {
		t.Fatalf("writable CA file was accepted: %v", err)
	}
}

func TestListRejectsNonAdvancingPagination(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Query().Get("list-type") != "2" {
			http.Error(writer, "unexpected request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>backup-test</Name><Prefix>repository/metadata/</Prefix><KeyCount>0</KeyCount><MaxKeys>2</MaxKeys><IsTruncated>true</IsTruncated><NextContinuationToken>stuck</NextContinuationToken></ListBucketResult>`)
	}))
	defer endpoint.Close()
	mirror := format.Mirror{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: endpoint.URL, Region: "us-east-1"}
	client, err := New(context.Background(), Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider("reader", "secret", ""), HTTPClient: endpoint.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.ListLimited(ctx, "metadata/", 1)
	if err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("nonadvancing mirror pagination was not rejected: %v", err)
	}
}

func TestCreateDispositionClassifiesHTTPOutcomes(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   CreateDisposition
	}{
		{"conflict", 409, CreateConflict},
		{"precondition", 412, CreateConflict},
		{"server error", 500, CreateAmbiguous},
		{"bad request", 400, CreateFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := httptest.NewTLSServer(httpErrorHandler(test.status))
			defer endpoint.Close()
			mirror := format.Mirror{Name: "local", Kind: format.MirrorBackupServer, S3URL: "s3://backup-test/repository", Endpoint: endpoint.URL, Region: "us-east-1"}
			client, err := New(context.Background(), Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider("writer", "secret", ""), HTTPClient: endpoint.Client()})
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("x")
			file := filepath.Join(t.TempDir(), "part")
			if err := os.WriteFile(file, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			key := "objects/" + HashBytes(payload).BLAKE2b + "/11111111111111111111111111111111"
			result := client.PutFile(context.Background(), key, file, HashBytes(payload))
			if result.Disposition != test.want {
				t.Fatalf("got=%v want=%v err=%v", result.Disposition, test.want, result.Err)
			}
		})
	}
}

type httpErrorHandler int

func (handler httpErrorHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(int(handler))
	_, _ = io.WriteString(writer, "<Error><Code>Failure</Code><Message>failure</Message></Error>")
}
