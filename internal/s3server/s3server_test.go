package s3server

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const (
	testBucket = "backup-test"
	testRegion = "us-east-1"
	accessKey  = "backup-access"
	secretKey  = "backup-secret"
)

type harness struct {
	t      *testing.T
	root   string
	server *Server
	http   *httptest.Server
	client *http.Client
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessAtRoot(t, t.TempDir())
}

func newHarnessAtRoot(t *testing.T, root string) *harness {
	t.Helper()
	now := time.Date(2026, 8, 2, 3, 0, 0, 0, time.UTC)
	server, err := Open(Config{
		Root: root, Bucket: testBucket, Region: testRegion, Now: func() time.Time { return now },
		MaximumObjectSize: 4 << 20,
		Credential:        Credential{AccessKey: accessKey, SecretKey: secretKey},
	})
	if err != nil {
		t.Fatalf("open server: %v", err)
	}
	httpServer := httptest.NewServer(server)
	h := &harness{t: t, root: root, server: server, http: httpServer, client: httpServer.Client(), now: now}
	t.Cleanup(func() {
		h.http.Close()
		if err := server.Close(); err != nil {
			t.Errorf("close server: %v", err)
		}
	})
	return h
}

func objectKey(data []byte, objectID byte) string {
	hash := blake2b.Sum512(data)
	return "objects/" + hex.EncodeToString(hash[:]) + "/" + strings.Repeat(hex.EncodeToString([]byte{objectID}), 16)
}

func (h *harness) request(method, key string, body []byte) *http.Request {
	h.t.Helper()
	request, err := http.NewRequest(method, h.http.URL+"/"+testBucket+"/"+key, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if method == http.MethodGet || method == http.MethodHead {
		request.Body = nil
		request.ContentLength = 0
	}
	h.sign(request, accessKey, secretKey, body)
	return request
}

func (h *harness) sign(request *http.Request, access, secret string, body []byte) {
	h.t.Helper()
	payload := sha256.Sum256(body)
	request.Header.Set("x-amz-content-sha256", hex.EncodeToString(payload[:]))
	signer := v4.NewSigner()
	if err := signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: access, SecretAccessKey: secret}, request, hex.EncodeToString(payload[:]), "s3", testRegion, h.now); err != nil {
		h.t.Fatalf("sign request: %v", err)
	}
}

func addPutHeaders(request *http.Request, body []byte) {
	md5Digest := md5.Sum(body)
	shaDigest := sha256.Sum256(body)
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(md5Digest[:]))
	request.Header.Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(shaDigest[:]))
	request.Header.Set("x-amz-sdk-checksum-algorithm", "SHA256")
}

func (h *harness) putRequest(key string, body []byte) *http.Request {
	h.t.Helper()
	request, err := http.NewRequest(http.MethodPut, h.http.URL+"/"+testBucket+"/"+key, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	addPutHeaders(request, body)
	h.sign(request, accessKey, secretKey, body)
	return request
}

func (h *harness) do(request *http.Request) *http.Response {
	h.t.Helper()
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	return response
}

func closeBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDefaultObjectLimitMatchesClientPartLimit(t *testing.T) {
	server, err := Open(Config{Root: t.TempDir(), Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	if server.config.MaximumObjectSize != 1<<30 {
		t.Fatalf("default maximum object size=%d, want 1 GiB", server.config.MaximumObjectSize)
	}
}

func TestOfficialAWSSignatureV4KnownAnswerVectors(t *testing.T) {
	// AWS's independently published S3 SigV4 examples:
	// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
	const (
		accessKey    = "AKIAIOSFODNN7EXAMPLE"
		secretKey    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		getSignature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	)
	getCanonical := "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	getStringToSign := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
	request, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Range", "bytes=0-9")
	request.Header.Set("x-amz-content-sha256", emptySHA256)
	request.Header.Set("x-amz-date", "20130524T000000Z")
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature="+getSignature)
	authorization, err := parseAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalRequest(request, authorization.SignedNames)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != getCanonical {
		t.Fatalf("canonical request:\n%s\nwant:\n%s", canonical, getCanonical)
	}
	canonicalDigest := sha256.Sum256([]byte(canonical))
	if got := hex.EncodeToString(canonicalDigest[:]); got != "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972" {
		t.Fatalf("canonical digest=%s", got)
	}
	if got := hmacHex(signingKey(secretKey, "20130524", "us-east-1", "s3"), getStringToSign); got != getSignature {
		t.Fatalf("GET vector signature=%s", got)
	}
	if err := verifySignature(request, authorization, secretKey); err != nil {
		t.Fatalf("official GET signature rejected: %v", err)
	}

	putCanonical := "PUT\n/test%24file.text\n\ndate:Fri, 24 May 2013 00:00:00 GMT\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\nx-amz-date:20130524T000000Z\nx-amz-storage-class:REDUCED_REDUNDANCY\n\ndate;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
	putDigest := sha256.Sum256([]byte(putCanonical))
	if got := hex.EncodeToString(putDigest[:]); got != "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d" {
		t.Fatalf("PUT canonical digest=%s", got)
	}
	putStringToSign := "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
	if got := hmacHex(signingKey(secretKey, "20130524", "us-east-1", "s3"), putStringToSign); got != "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd" {
		t.Fatalf("PUT vector signature=%s", got)
	}
}

func TestEverySecurityRelevantHeaderMustBeSigned(t *testing.T) {
	request, err := http.NewRequest(http.MethodPut, "https://example.invalid/object", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-MD5", "digest")
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("If-Match", "etag")
	request.Header.Set("If-Modified-Since", "date")
	request.Header.Set("If-Unmodified-Since", "date")
	request.Header.Set("If-Range", "etag")
	request.Header.Set("Range", "bytes=0-1")
	request.Header.Set("Date", "date")
	for _, name := range []string{
		"x-amz-content-sha256", "x-amz-date", "x-amz-security-token",
		"x-amz-checksum-sha256", "x-amz-checksum-mode", "x-amz-sdk-checksum-algorithm", "x-amz-user-agent",
	} {
		request.Header.Set(name, "value")
	}
	required := []string{
		"host", "content-length", "content-md5", "if-none-match", "if-match",
		"if-modified-since", "if-unmodified-since", "if-range", "range", "date",
		"x-amz-content-sha256", "x-amz-date", "x-amz-security-token",
		"x-amz-checksum-sha256", "x-amz-checksum-mode", "x-amz-sdk-checksum-algorithm", "x-amz-user-agent",
	}
	for _, omitted := range required {
		t.Run(omitted, func(t *testing.T) {
			lookup := make(map[string]struct{}, len(required)-1)
			for _, name := range required {
				if name != omitted {
					lookup[name] = struct{}{}
				}
			}
			err := requireSecurityHeadersSigned(request, parsedAuthorization{SignedLookup: lookup})
			if err == nil || !strings.Contains(err.Error(), omitted) {
				t.Fatalf("unsigned %s was accepted: %v", omitted, err)
			}
		})
	}
	lookup := make(map[string]struct{}, len(required))
	for _, name := range required {
		lookup[name] = struct{}{}
	}
	request.Header.Set("User-Agent", "not security-relevant")
	if err := requireSecurityHeadersSigned(request, parsedAuthorization{SignedLookup: lookup}); err != nil {
		t.Fatalf("complete signed-header set rejected: %v", err)
	}
}

func TestRequestDateRejectsFarFutureWithoutDurationOverflow(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("x-amz-date", "99991231T235959Z")
	authorization := parsedAuthorization{Scope: credentialScope{Date: "99991231"}}
	now := time.Date(2026, 8, 2, 3, 0, 0, 0, time.UTC)
	if err := validateRequestDate(request, authorization, now, 15*time.Minute); err == nil {
		t.Fatal("far-future request date was accepted after time.Duration overflow")
	}
}

func TestListingIsSortedBoundedAndCancelable(t *testing.T) {
	h := newHarness(t)
	objectsDirectory := filepath.Join(h.root, "objects")
	for index := 0; index < 1500; index++ {
		hash := fmt.Sprintf("%0128x", index+1)
		objectID := fmt.Sprintf("%032x", 1500-index)
		directory := filepath.Join(objectsDirectory, hash)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, objectID), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.server.rebuildListingIndices()
	inspections := h.server.listing["objects"].inspections
	selected, err := h.server.walkObjects(context.Background(), "objects/", "", 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 17 {
		t.Fatalf("selected %d objects", len(selected))
	}
	for index := 1; index < len(selected); index++ {
		if selected[index-1].Key >= selected[index].Key {
			t.Fatalf("listing is not sorted at %q and %q", selected[index-1].Key, selected[index].Key)
		}
	}
	all, err := h.server.walkObjects(context.Background(), "objects/", selected[len(selected)-1].Key, 17)
	if err != nil || len(all) != 17 || all[0].Key <= selected[len(selected)-1].Key {
		t.Fatalf("continuation page=%v err=%v", all, err)
	}
	if after := h.server.listing["objects"].inspections; after != inspections {
		t.Fatalf("paginated listing rescanned the filesystem: inspections %d -> %d", inspections, after)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.server.walkObjects(ctx, "objects/", "", 17); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled listing error=%v", err)
	}
}

func TestListingIgnoresUnrelatedBackendSubtrees(t *testing.T) {
	h := newHarness(t)
	tip := strings.Repeat("a", 64)
	hash := strings.Repeat("b", 128)
	objectID := strings.Repeat("c", 32)
	key := "metadata/manifests/" + tip + "/" + hash + "/" + objectID
	path := filepath.Join(append([]string{h.root}, strings.Split(key, "/")...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(h.root, "objects", "unexpected")
	if err := os.MkdirAll(filepath.Dir(unrelated), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(unrelated, 0o600); err != nil {
		t.Fatal(err)
	}
	h.server.rebuildListingIndices()
	selected, err := h.server.walkObjects(context.Background(), "metadata/manifests/", "", 10)
	if err != nil || len(selected) != 1 || selected[0].Key != key {
		t.Fatalf("prefix-scoped listing=%#v err=%v", selected, err)
	}
}

func TestCreateGetHeadListAndImmutability(t *testing.T) {
	h := newHarness(t)
	payload := []byte("durable object")
	key := objectKey(payload, 1)

	response := h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT status %d: %s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	response = h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("overwrite status %d: %s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	get := h.request(http.MethodGet, key, nil)
	response = h.do(get)
	if response.StatusCode != http.StatusOK || string(closeBody(t, response)) != string(payload) {
		t.Fatalf("GET failed: status=%d", response.StatusCode)
	}

	head := h.request(http.MethodHead, key, nil)
	head.Header.Set("x-amz-checksum-mode", "ENABLED")
	h.sign(head, accessKey, secretKey, nil)
	response = h.do(head)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status %d", response.StatusCode)
	}
	if body := closeBody(t, response); len(body) != 0 {
		t.Fatalf("HEAD returned a body: %q", body)
	}
	shaDigest := sha256.Sum256(payload)
	if response.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(shaDigest[:]) || response.Header.Get("x-amz-checksum-type") != "FULL_OBJECT" {
		t.Fatalf("HEAD returned wrong checksums: %v", response.Header)
	}

	list, err := http.NewRequest(http.MethodGet, h.http.URL+"/"+testBucket+"?list-type=2&prefix=objects%2F&max-keys=10", nil)
	if err != nil {
		t.Fatal(err)
	}
	h.sign(list, accessKey, secretKey, nil)
	response = h.do(list)
	listBody := closeBody(t, response)
	if response.StatusCode != http.StatusOK || !bytes.Contains(listBody, []byte(key)) {
		t.Fatalf("LIST status=%d body=%s", response.StatusCode, listBody)
	}
}

func TestAuthenticationMethodsAndRequiredSignedHeaders(t *testing.T) {
	h := newHarness(t)
	payload := []byte("permissions")
	key := objectKey(payload, 2)

	tests := []struct {
		name    string
		request func() *http.Request
		want    int
	}{
		{"unknown credential cannot put", func() *http.Request {
			r := h.putRequest(key, payload)
			h.sign(r, "unknown", secretKey, payload)
			return r
		}, http.StatusForbidden},
		{"delete forbidden", func() *http.Request { return h.request(http.MethodDelete, key, nil) }, http.StatusForbidden},
		{"post unsupported", func() *http.Request { return h.request(http.MethodPost, key, nil) }, http.StatusMethodNotAllowed},
		{"unsigned conditional", func() *http.Request {
			r, _ := http.NewRequest(http.MethodPut, h.http.URL+"/"+testBucket+"/"+key, bytes.NewReader(payload))
			shaDigest := sha256.Sum256(payload)
			r.Header.Set("x-amz-content-sha256", hex.EncodeToString(shaDigest[:]))
			h.sign(r, accessKey, secretKey, payload)
			addPutHeaders(r, payload)
			return r
		}, http.StatusForbidden},
		{"missing conditional", func() *http.Request {
			r := h.putRequest(key, payload)
			r.Header.Del("If-None-Match")
			h.sign(r, accessKey, secretKey, payload)
			return r
		}, http.StatusPreconditionFailed},
		{"missing md5", func() *http.Request {
			r := h.putRequest(key, payload)
			r.Header.Del("Content-MD5")
			h.sign(r, accessKey, secretKey, payload)
			return r
		}, http.StatusBadRequest},
		{"unsigned checksum mode", func() *http.Request {
			r := h.request(http.MethodHead, key, nil)
			r.Header.Set("x-amz-checksum-mode", "ENABLED")
			return r
		}, http.StatusForbidden},
		{"streaming payload", func() *http.Request {
			r := h.putRequest(key, payload)
			r.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
			return r
		}, http.StatusForbidden},
		{"unsigned payload", func() *http.Request {
			r := h.putRequest(key, payload)
			r.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
			return r
		}, http.StatusForbidden},
		{"unknown aws header", func() *http.Request {
			r := h.putRequest(key, payload)
			r.Header.Set("x-amz-copy-source", "/backup-test/source")
			h.sign(r, accessKey, secretKey, payload)
			return r
		}, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := h.do(test.request())
			body := closeBody(t, response)
			if response.StatusCode != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.StatusCode, test.want, body)
			}
		})
	}
}

func TestNonPutRequestsRequireAnEmptyFixedPayload(t *testing.T) {
	h := newHarness(t)
	payload := []byte("unexpected body")
	key := objectKey(payload, 9)

	withBody, err := http.NewRequest(http.MethodGet, h.http.URL+"/"+testBucket+"/"+key, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	h.sign(withBody, accessKey, secretKey, payload)
	response := h.do(withBody)
	body := closeBody(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET body status=%d body=%s", response.StatusCode, body)
	}

	wrongDigest := h.request(http.MethodGet, key, nil)
	h.sign(wrongDigest, accessKey, secretKey, payload)
	response = h.do(wrongDigest)
	body = closeBody(t, response)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET nonempty payload digest status=%d body=%s", response.StatusCode, body)
	}
}

type failFirstBodyWrite struct {
	header   http.Header
	statuses []int
	body     bytes.Buffer
	failed   bool
}

func (writer *failFirstBodyWrite) Header() http.Header {
	if writer.header == nil {
		writer.header = make(http.Header)
	}
	return writer.header
}

func (writer *failFirstBodyWrite) WriteHeader(status int) {
	writer.statuses = append(writer.statuses, status)
}

func (writer *failFirstBodyWrite) Write(data []byte) (int, error) {
	if !writer.failed && len(writer.statuses) != 0 && writer.statuses[len(writer.statuses)-1] == http.StatusOK {
		writer.failed = true
		count := 3
		if len(data) < count {
			count = len(data)
		}
		_, _ = writer.body.Write(data[:count])
		return count, errors.New("injected response write failure")
	}
	return writer.body.Write(data)
}

func TestCommittedGETWriteFailureDoesNotAppendXMLError(t *testing.T) {
	h := newHarness(t)
	payload := []byte("verified object body")
	key := objectKey(payload, 11)
	response := h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	writer := &failFirstBodyWrite{}
	request := h.request(http.MethodGet, key, nil)
	request.URL.Scheme, request.URL.Host = "", ""
	h.server.ServeHTTP(writer, request)
	if len(writer.statuses) != 1 || writer.statuses[0] != http.StatusOK {
		t.Fatalf("GET wrote response statuses %v body=%s", writer.statuses, writer.body.String())
	}
	if got := writer.body.String(); got != string(payload[:3]) || strings.Contains(got, "<Error>") {
		t.Fatalf("GET appended an error response after body failure: %q", got)
	}
}

func TestRandomFailureReturnsInternalErrorInsteadOfPanicking(t *testing.T) {
	h := newHarness(t)
	prior := randomSource
	randomSource = errorReader{}
	t.Cleanup(func() { randomSource = prior })

	request := h.request(http.MethodGet, objectKey([]byte("missing"), 10), nil)
	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("injected random failure") }

func TestWrongAndTruncatedBodiesNeverPublish(t *testing.T) {
	h := newHarness(t)
	payload := []byte("complete")
	key := objectKey(payload, 3)

	wrong := h.putRequest(key, payload)
	wrong.Body = io.NopCloser(strings.NewReader("corrupt!"))
	response := h.do(wrong)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong body status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	truncated := h.putRequest(key, payload)
	truncated.Body = io.NopCloser(bytes.NewReader(payload[:3]))
	recorder := httptest.NewRecorder()
	h.server.ServeHTTP(recorder, truncated)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("truncated body status=%d body=%s", recorder.Code, recorder.Body.Bytes())
	}

	response = h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid retry status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
}

func TestConcurrentCreateHasExactlyOneWinner(t *testing.T) {
	h := newHarness(t)
	payload := []byte("one winner")
	key := objectKey(payload, 4)
	const requestCount = 24
	requests := make([]*http.Request, requestCount)
	for index := range requests {
		requests[index] = h.putRequest(key, payload)
	}
	type outcome struct {
		status int
		err    error
	}
	outcomes := make(chan outcome, requestCount)
	for _, request := range requests {
		go func(request *http.Request) {
			response, err := h.client.Do(request)
			if err != nil {
				outcomes <- outcome{err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			outcomes <- outcome{status: response.StatusCode, err: errors.Join(readErr, closeErr)}
		}(request)
	}
	successes, conflicts := 0, 0
	for range requestCount {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("concurrent request: %v", outcome.err)
		}
		switch outcome.status {
		case http.StatusOK:
			successes++
		case http.StatusPreconditionFailed:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent status %d", outcome.status)
		}
	}
	if successes != 1 || conflicts != requestCount-1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestChecksumHeadDetectsBackendCorruptionWithoutBody(t *testing.T) {
	h := newHarness(t)
	payload := []byte("healthy")
	key := objectKey(payload, 5)
	response := h.do(h.putRequest(key, payload))
	closeBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatal("put failed")
	}
	path := filepath.Join(append([]string{h.root}, strings.Split(key, "/")...)...)
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	head := h.request(http.MethodHead, key, nil)
	head.Header.Set("x-amz-checksum-mode", "ENABLED")
	h.sign(head, accessKey, secretKey, nil)
	response = h.do(head)
	body := closeBody(t, response)
	if response.StatusCode != http.StatusInternalServerError || len(body) != 0 || response.ContentLength == int64(len(payload)) {
		t.Fatalf("corrupt HEAD status=%d content-length=%d body=%q", response.StatusCode, response.ContentLength, body)
	}
}

func TestBackendSymlinkCannotEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "objects")); err != nil {
		t.Fatal(err)
	}
	h := newHarnessAtRoot(t, root)
	payload := []byte("escape attempt")
	key := objectKey(payload, 6)
	response := h.do(h.putRequest(key, payload))
	closeBody(t, response)
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.StatusCode)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("server escaped data root: %v", entries)
	}
}

func TestDataRootSymlinkIsRejected(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "root")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	server, err := Open(Config{Root: link, Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if server != nil {
		_ = server.Close()
	}
	if err == nil {
		t.Fatal("data-root symlink was accepted")
	}
	entries, readErr := os.ReadDir(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("server wrote through data-root symlink: %v", entries)
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("data-root symlink target mode changed to %04o", info.Mode().Perm())
	}
}

func TestRootLockAndStaleUploadCleanup(t *testing.T) {
	root := t.TempDir()
	internal := filepath.Join(root, internalDirectory, temporaryDirectory)
	if err := os.MkdirAll(internal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(internal, "stale"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarnessAtRoot(t, root)
	if _, err := os.Stat(filepath.Join(internal, "stale")); !os.IsNotExist(err) {
		t.Fatalf("stale upload was not removed: %v", err)
	}
	_, err := Open(Config{Root: root, Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if err == nil || !strings.Contains(err.Error(), "already locked") {
		t.Fatalf("second server lock unexpectedly succeeded: %v", err)
	}
	_ = h
}

func TestRootLockRejectsUnexpectedType(t *testing.T) {
	root := t.TempDir()
	internal := filepath.Join(root, internalDirectory)
	if err := os.Mkdir(internal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(internal, lockFilename), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := Open(Config{Root: root, Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if server != nil {
		_ = server.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("FIFO server lock was accepted: %v", err)
	}
}

func TestUnexpectedStaleUploadTypeFailsClosed(t *testing.T) {
	root := t.TempDir()
	temp := filepath.Join(root, internalDirectory, temporaryDirectory)
	if err := os.MkdirAll(filepath.Join(temp, "unexpected"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Open(Config{Root: root, Bucket: testBucket, Region: testRegion, Credential: Credential{AccessKey: accessKey, SecretKey: secretKey}})
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("unexpected stale type was accepted: %v", err)
	}
}
