package objectstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"backup/internal/format"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type integrityHTTPClient func(*http.Request) (*http.Response, error)

func (client integrityHTTPClient) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

func TestReadFailuresDistinguishCorruptionAbsenceAndUnavailableCapabilities(t *testing.T) {
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	expected := HashBytes([]byte("healthy"))
	sha, _ := hex.DecodeString(expected.SHA256)
	validSHA := base64.StdEncoding.EncodeToString(sha)
	for _, test := range []struct {
		name                              string
		status                            int
		size                              string
		checksum, checksumType, integrity string
		kind                              string
		want                              error
	}{
		{name: "healthy", status: 200, size: "7", checksum: validSHA},
		{name: "missing", status: 404, want: ErrMissing},
		{name: "access denied", status: 403},
		{name: "transient server failure", status: 500},
		{name: "server proven corrupt", status: 500, integrity: "corrupt", want: ErrCorrupt},
		{name: "nonserver cannot assert custom integrity", status: 500, integrity: "corrupt", kind: format.MirrorCloudflareR2},
		{name: "wrong size", status: 200, size: "6", checksum: validSHA, want: ErrCorrupt},
		{name: "wrong full checksum", status: 200, size: "7", checksum: base64.StdEncoding.EncodeToString(make([]byte, 32)), want: ErrCorrupt},
		{name: "missing checksum", status: 200, size: "7"},
		{name: "malformed checksum", status: 200, size: "7", checksum: "not-a-digest"},
		{name: "unsupported checksum type", status: 200, size: "7", checksum: validSHA, checksumType: "COMPOSITE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind := test.kind
			if kind == "" {
				kind = format.MirrorBackupServer
			}
			client, err := New(context.Background(), Options{Mirror: format.Mirror{Name: "test", Kind: kind, S3URL: "s3://backup-test/repository", Endpoint: "https://objects.example", Region: "us-east-1"}, CredentialsProvider: credentials.NewStaticCredentialsProvider("reader", "reader-secret", ""), HTTPClient: integrityHTTPClient(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodHead {
					t.Fatalf("unexpected body request: %s", request.Method)
				}
				header := http.Header{}
				if test.size != "" {
					header.Set("Content-Length", test.size)
				}
				header.Set("X-Amz-Checksum-Sha256", test.checksum)
				header.Set("X-Amz-Checksum-Type", test.checksumType)
				header.Set("X-Backup-Integrity", test.integrity)
				return &http.Response{StatusCode: test.status, Header: header, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Audit(context.Background(), "objects/"+expected.BLAKE2b+"/"+strings.Repeat("a", 32), expected)
			if test.name == "healthy" && err != nil {
				t.Fatal(err)
			}
			if test.name != "healthy" && err == nil {
				t.Fatal("invalid or unverifiable object passed audit")
			}
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("classification: %v; want %v", err, test.want)
				}
			} else if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrMissing) {
				t.Fatalf("unknown incorrectly promoted to data loss: %v", err)
			}
		})
	}
}
