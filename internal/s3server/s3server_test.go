package s3server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSigV4PutGet(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	payload := []byte("hello")
	put := server.newRequest(t, http.MethodPut, "/bucket/key", payload, payloadHash(payload))
	resp := server.do(t, put)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	get := server.newRequest(t, http.MethodGet, "/bucket/key", nil, emptySHA256)
	resp = server.do(t, get)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected body: %s", string(data))
	}
}

func TestRejectUnsignedPayload(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	payload := []byte("hello")
	req := server.newRequest(t, http.MethodPut, "/bucket/key", payload, "UNSIGNED-PAYLOAD")
	resp := server.do(t, req)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected failure for unsigned payload")
	}
}

func TestStreamingPayload(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	payload := []byte("streaming payload")
	request := server.newChunkedRequest(t, "PUT", "/bucket/stream", payload, "", "")
	resp := server.do(t, request)
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestStreamingPayloadTrailer(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	payload := []byte("trailer payload")
	checksum := sha256.Sum256(payload)
	trailerValue := base64.StdEncoding.EncodeToString(checksum[:])
	request := server.newChunkedRequest(t, "PUT", "/bucket/trailer", payload, "x-amz-checksum-sha256", trailerValue)
	resp := server.do(t, request)
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestQueryCanonicalization(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	payload := []byte("query payload")
	req := server.newRequest(t, http.MethodPut, "/bucket/query?space=a+b&slash=a%2Fb&plain=z", payload, payloadHash(payload))
	resp := server.do(t, req)
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestRejectInvalidRequests(t *testing.T) {
	server := &s3ServerHarness{}
	server.start(t)
	defer server.close()

	type testCase struct {
		name       string
		makeReq    func(t *testing.T) *http.Request
		wantStatus int
	}

	tests := []testCase{
		{
			name: "missing x-amz-content-sha256",
			makeReq: func(t *testing.T) *http.Request {
				payload := []byte("hello")
				req := server.newRequest(t, http.MethodPut, "/bucket/key", payload, payloadHash(payload))
				req.Header.Del("x-amz-content-sha256")
				return req
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing authorization",
			makeReq: func(t *testing.T) *http.Request {
				payload := []byte("hello")
				req := server.newRequest(t, http.MethodPut, "/bucket/key", payload, payloadHash(payload))
				req.Header.Del("Authorization")
				return req
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "signature mismatch",
			makeReq: func(t *testing.T) *http.Request {
				payload := []byte("hello")
				req := server.newRequest(t, http.MethodPut, "/bucket/key", payload, payloadHash(payload))
				req.Header.Set("x-amz-date", "20250101T000001Z")
				return req
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "invalid key contains ..",
			makeReq: func(t *testing.T) *http.Request {
				payload := []byte("hello")
				return server.newRequest(t, http.MethodPut, "/bucket/../key", payload, payloadHash(payload))
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "get requires empty payload hash",
			makeReq: func(t *testing.T) *http.Request {
				return server.newRequest(t, http.MethodGet, "/bucket/key", nil, "deadbeef")
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "delete is not allowed",
			makeReq: func(t *testing.T) *http.Request {
				return server.newRequest(t, http.MethodDelete, "/bucket/key", nil, emptySHA256)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "method not allowed",
			makeReq: func(t *testing.T) *http.Request {
				return server.newRequest(t, http.MethodPost, "/bucket/key", nil, emptySHA256)
			},
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := test.makeReq(t)
			resp := server.do(t, req)
			if resp.StatusCode != test.wantStatus {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				t.Fatalf("unexpected status: got=%d want=%d body=%s", resp.StatusCode, test.wantStatus, string(body))
			}
		})
	}
}

type s3ServerHarness struct {
	server    *httptest.Server
	client    *http.Client
	accessKey string
	secretKey string
}

func (h *s3ServerHarness) start(t *testing.T) {
	h.accessKey = "test"
	h.secretKey = "secret"
	h.server = httptest.NewTLSServer(&Server{Dir: t.TempDir(), AccessKey: h.accessKey, SecretKey: h.secretKey, Region: "us-east-1"})
	baseClient := h.server.Client()
	transport := baseClient.Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	h.client = &http.Client{Transport: transport}
}

func (h *s3ServerHarness) close() {
	h.server.Close()
}

func (h *s3ServerHarness) do(t *testing.T, req *http.Request) *http.Response {
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp
}

func (h *s3ServerHarness) newRequest(t *testing.T, method string, path string, payload []byte, payloadHash string) *http.Request {
	url := h.server.URL + path
	var body io.ReadSeeker
	if payload != nil {
		body = bytes.NewReader(payload)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("x-amz-date", "20250101T000000Z")
	req.Header.Set("x-amz-content-sha256", payloadHash)
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	signRequest(t, req, payloadHash, h.accessKey, h.secretKey, "us-east-1", signedHeaders)
	return req
}

func (h *s3ServerHarness) newChunkedRequest(t *testing.T, method string, path string, payload []byte, trailerName string, trailerValue string) *http.Request {
	url := h.server.URL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	amzDate := "20250101T000000Z"
	scope := credentialScope{AccessKey: h.accessKey, Date: amzDate[:8], Region: "us-east-1", Service: "s3"}
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	payloadMode := streamingPayload
	if trailerName != "" {
		payloadMode = streamingPayloadTrailer
		req.Header.Set("x-amz-trailer", trailerName)
		signedHeaders = append(signedHeaders, "x-amz-trailer")
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadMode)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(payload)))

	canonical, err := canonicalRequest(req, signedHeaders, payloadMode)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	signature := h.signCanonical(t, canonical, scope, amzDate)
	signer := chunkSigner{SeedSignature: signature, SigningKey: signingKey(h.secretKey, scope.Date, scope.Region, scope.Service), Scope: scope.String(), AmzDate: amzDate}
	body := buildChunkedBody(signer, payload, trailerName, trailerValue)
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	auth := buildAuthorization(scope, signature, signedHeaders)
	req.Header.Set("Authorization", auth)
	return req
}

func (h *s3ServerHarness) signCanonical(t *testing.T, canonical string, scope credentialScope, amzDate string) string {
	stringToSign := strings.Join([]string{aws4Algorithm, amzDate, scope.String(), fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))}, "\n")
	return hmacHex(signingKey(h.secretKey, scope.Date, scope.Region, scope.Service), stringToSign)
}

func signRequest(t *testing.T, req *http.Request, payloadHash string, accessKey string, secretKey string, region string, signedHeaders []string) {
	credential := credentialScope{AccessKey: accessKey, Date: "20250101", Region: region, Service: "s3"}
	canonical, err := canonicalRequest(req, signedHeaders, payloadHash)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	stringToSign := strings.Join([]string{aws4Algorithm, req.Header.Get("x-amz-date"), credential.String(), fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))}, "\n")
	signature := hmacHex(signingKey(secretKey, credential.Date, credential.Region, credential.Service), stringToSign)
	req.Header.Set("Authorization", buildAuthorization(credential, signature, signedHeaders))
}

func buildAuthorization(scope credentialScope, signature string, signedHeaders []string) string {
	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s", aws4Algorithm, scope.AccessKey, scope.String(), strings.Join(signedHeaders, ";"), signature)
}

func buildChunkedBody(signer chunkSigner, payload []byte, trailerName string, trailerValue string) []byte {
	chunkSig := chunkSignatureFor(signer, signer.SeedSignature, payload)
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%x;chunk-signature=%s\r\n", len(payload), chunkSig))
	buffer.Write(payload)
	buffer.WriteString("\r\n")
	finalSig := chunkSignatureFor(signer, chunkSig, nil)
	if trailerName == "" {
		buffer.WriteString(fmt.Sprintf("0;chunk-signature=%s\r\n\r\n", finalSig))
		return buffer.Bytes()
	}
	buffer.WriteString(fmt.Sprintf("0;chunk-signature=%s\r\n", finalSig))
	payloadString := fmt.Sprintf("%s:%s\n", strings.ToLower(trailerName), trailerValue)
	trailerSig := trailerSignatureFor(signer, finalSig, payloadString)
	buffer.WriteString(fmt.Sprintf("%s:%s\r\n", trailerName, trailerValue))
	buffer.WriteString(fmt.Sprintf("x-amz-trailer-signature:%s\r\n\r\n", trailerSig))
	return buffer.Bytes()
}

func payloadHash(payload []byte) string {
	hash := sha256.Sum256(payload)
	return fmt.Sprintf("%x", hash)
}
