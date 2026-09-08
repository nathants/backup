package s3server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func requestLog(t *testing.T, data []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var entry map[string]any
	if err := decoder.Decode(&entry); err != nil {
		t.Fatalf("decode request log: %v; %q", err, data)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one request log: %v; %q", err, data)
	}
	return entry
}

func TestRequestLogsActualStatusAndInternalCause(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.server.config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	payload := []byte("audit payload")
	key := objectKey(payload, 23)
	request := h.putRequest(key, payload)
	request.URL.Scheme, request.URL.Host = "", ""
	response := httptest.NewRecorder()
	h.server.ServeHTTP(response, request)
	entry := requestLog(t, logs.Bytes())
	if response.Code != http.StatusOK || entry["status"] != float64(http.StatusOK) || entry["level"] != "INFO" {
		t.Errorf("successful PUT response=%d log=%v", response.Code, entry)
	}
	logs.Reset()
	original := h.server.tempFD
	h.server.tempFD = -1
	t.Cleanup(func() { h.server.tempFD = original })
	request = h.putRequest(objectKey(payload, 24), payload)
	request.URL.Scheme, request.URL.Host = "", ""
	response = httptest.NewRecorder()
	h.server.ServeHTTP(response, request)
	entry = requestLog(t, logs.Bytes())
	cause, _ := entry["error"].(string)
	if response.Code != http.StatusInternalServerError || entry["status"] != float64(http.StatusInternalServerError) || entry["level"] != "ERROR" || !strings.Contains(cause, "create upload temp") || !strings.Contains(cause, unix.EBADF.Error()) {
		t.Fatalf("internal failure response=%d log=%v", response.Code, entry)
	}
	if !strings.Contains(response.Body.String(), "<Message>internal server error</Message>") || strings.Contains(response.Body.String(), "upload temp") || strings.Contains(response.Body.String(), unix.EBADF.Error()) {
		t.Fatalf("internal cause escaped to client: %s", response.Body.String())
	}
}

func TestRequestLogPreservesFailureAfterCommittedResponse(t *testing.T) {
	h := newHarness(t)
	payload := []byte("audit response write failure")
	key := objectKey(payload, 25)
	request := h.putRequest(key, payload)
	request.URL.Scheme, request.URL.Host = "", ""
	response := httptest.NewRecorder()
	h.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("positive control failed: %d %s", response.Code, response.Body.String())
	}
	var logs bytes.Buffer
	h.server.config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	request = h.request(http.MethodGet, key, nil)
	request.URL.Scheme, request.URL.Host = "", ""
	writer := &failFirstBodyWrite{}
	h.server.ServeHTTP(writer, request)
	entry := requestLog(t, logs.Bytes())
	cause, _ := entry["error"].(string)
	if entry["status"] != float64(http.StatusOK) || entry["level"] != "ERROR" || !strings.Contains(cause, "injected response write failure") {
		t.Fatalf("committed failure log=%v", entry)
	}
	if len(writer.statuses) != 1 || writer.statuses[0] != http.StatusOK || writer.body.String() != string(payload[:3]) {
		t.Fatalf("failure rewrote committed response: %v %q", writer.statuses, writer.body.String())
	}
}

func TestRequestLogReadListAndClientErrors(t *testing.T) {
	h := newHarness(t)
	payload := []byte("read audit fixture")
	key := objectKey(payload, 26)
	request := h.putRequest(key, payload)
	request.URL.Scheme, request.URL.Host = "", ""
	response := httptest.NewRecorder()
	h.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("positive control: %d %s", response.Code, response.Body.String())
	}
	var logs bytes.Buffer
	h.server.config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	for _, test := range []struct {
		method, key string
		status      int
		code        string
	}{
		{http.MethodGet, key, http.StatusOK, ""},
		{http.MethodHead, key, http.StatusOK, ""},
		{http.MethodGet, "?list-type=2", http.StatusOK, ""},
		{http.MethodDelete, key, http.StatusForbidden, "AccessDenied"},
		{http.MethodGet, objectKey(payload, 27), http.StatusNotFound, "NoSuchKey"},
	} {
		logs.Reset()
		request := h.request(test.method, test.key, nil)
		if test.key == "?list-type=2" {
			request.URL.Path = "/" + testBucket
			h.sign(request, accessKey, secretKey, nil)
		}
		request.URL.Scheme, request.URL.Host = "", ""
		response := httptest.NewRecorder()
		h.server.ServeHTTP(response, request)
		entry := requestLog(t, logs.Bytes())
		if response.Code != test.status || entry["status"] != float64(test.status) || entry["code"] != test.code || entry["level"] != "INFO" {
			t.Fatalf("%s %s: response=%d log=%v", test.method, test.key, response.Code, entry)
		}
	}
}

type logErrorReader struct{ err error }

func (reader logErrorReader) Read([]byte) (int, error) { return 0, reader.err }

func TestRequestLogRedactsCredentialsAndEscapesControls(t *testing.T) {
	h := newHarness(t)
	h.server.config.Credential = Credential{AccessKey: "test-access-value", SecretKey: "test-secret/value", SessionToken: "test-session-value"}
	var logs bytes.Buffer
	h.server.config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	request := h.request(http.MethodGet, "unused", nil)
	request.URL.Scheme, request.URL.Host = "", ""
	request.URL.Path = "/" + h.server.config.Credential.SecretKey
	request.URL.RawPath = "/test-secret%2Fvalue"
	request.Header.Set("x-amz-security-token", "received-token-value")
	authorization := request.Header.Get("Authorization")
	prior := randomSource
	randomSource = logErrorReader{err: errors.New("entropy failure\n\x1b[31m " + authorization + " " + h.server.config.Credential.AccessKey + " " + h.server.config.Credential.SecretKey + " " + h.server.config.Credential.SessionToken + " received-token-value")}
	t.Cleanup(func() { randomSource = prior })
	response := httptest.NewRecorder()
	h.server.ServeHTTP(response, request)
	entry := requestLog(t, logs.Bytes())
	cause, _ := entry["error"].(string)
	if response.Code != http.StatusInternalServerError || entry["status"] != float64(http.StatusInternalServerError) || entry["request_id"] != "unavailable" || !strings.Contains(cause, "generate request ID: read cryptographic randomness: entropy failure") || !strings.Contains(cause, "[redacted]") {
		t.Fatalf("missing safe cause or status: %v", entry)
	}
	for _, value := range []string{authorization, h.server.config.Credential.AccessKey, h.server.config.Credential.SecretKey, "test-secret%2Fvalue", h.server.config.Credential.SessionToken, "received-token-value"} {
		if strings.Contains(logs.String(), value) || strings.Contains(cause, value) {
			t.Fatal("credential/header leaked into request log")
		}
	}
	if bytes.Contains(logs.Bytes(), []byte{0x1b}) || bytes.Count(logs.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("log controls were not escaped: %q", logs.String())
	}
	if !strings.Contains(response.Body.String(), "<Message>internal server error</Message>") || strings.Contains(response.Body.String(), "entropy failure") {
		t.Fatalf("internal cause leaked to wire: %s", response.Body.String())
	}
}

type logFailWriter struct{ *httptest.ResponseRecorder }

func (writer logFailWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected error-response write failure")
}

func TestRequestLogRecordsErrorResponseWriteFailure(t *testing.T) {
	h := newHarness(t)
	var logs bytes.Buffer
	h.server.config.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	request := h.request(http.MethodGet, objectKey([]byte("missing"), 28), nil)
	request.URL.Scheme, request.URL.Host = "", ""
	request.Header.Del("Authorization")
	writer := logFailWriter{httptest.NewRecorder()}
	h.server.ServeHTTP(writer, request)
	entry := requestLog(t, logs.Bytes())
	cause, _ := entry["error"].(string)
	if writer.Code != http.StatusForbidden || entry["status"] != float64(http.StatusForbidden) || entry["level"] != "ERROR" || !strings.Contains(cause, "missing authorization header") || !strings.Contains(cause, "injected error-response write failure") {
		t.Fatalf("error response failure was lost: %v", entry)
	}
}

func TestResponseStatusTracksImplicitAndFinalHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &trackedResponseWriter{ResponseWriter: recorder}
	if _, err := writer.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	writer.WriteHeader(http.StatusInternalServerError)
	if writer.status != http.StatusOK || recorder.Code != http.StatusOK || writer.Unwrap() != recorder {
		t.Fatalf("implicit/first status not preserved: %d %d", writer.status, recorder.Code)
	}
	underlying := &failFirstBodyWrite{}
	writer = &trackedResponseWriter{ResponseWriter: underlying}
	writer.WriteHeader(http.StatusEarlyHints)
	writer.WriteHeader(http.StatusNoContent)
	writer.WriteHeader(http.StatusInternalServerError)
	if writer.status != http.StatusNoContent || len(underlying.statuses) != 2 || underlying.statuses[0] != http.StatusEarlyHints || underlying.statuses[1] != http.StatusNoContent {
		t.Fatalf("interim/final status not preserved: %d %v", writer.status, underlying.statuses)
	}
}
