package integration

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDockerServerConcurrentCreateRetryLostResponseAndPagination(t *testing.T) {
	requireDockerIntegration(t)
	buildDockerServer(t)
	h := newDockerHarness(t)
	h.start()

	payload := []byte("concurrent docker create")
	key := objectKey(payload, 21)
	const contenders = 24
	statuses := make(chan int, contenders)
	errors := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := h.client.Do(h.putRequest(key, payload))
			if err != nil {
				errors <- err
				return
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				errors <- readErr
				return
			}
			if closeErr != nil {
				errors <- closeErr
				return
			}
			statuses <- response.StatusCode
		}()
	}
	wait.Wait()
	close(statuses)
	close(errors)
	for err := range errors {
		t.Errorf("concurrent request: %v", err)
	}
	successes, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusPreconditionFailed:
			conflicts++
		default:
			t.Errorf("unexpected concurrent status %d", status)
		}
	}
	if successes != 1 || conflicts != contenders-1 {
		t.Fatalf("concurrent creates: successes=%d conflicts=%d", successes, conflicts)
	}
	response := h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("retry status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	lostPayload := []byte("created even though the caller loses the response")
	lostKey := objectKey(lostPayload, 22)
	proxy, forwarded := lostResponseProxy(t, h)
	lostRequest, err := http.NewRequest(http.MethodPut, proxy.URL+"/"+testBucket+"/"+lostKey, bytes.NewReader(lostPayload))
	if err != nil {
		t.Fatal(err)
	}
	addDockerPutHeaders(lostRequest, lostPayload)
	h.sign(lostRequest, accessKey, secretKey, lostPayload)
	lostClient := proxy.Client()
	lostClient.Timeout = 15 * time.Second
	if response, err := lostClient.Do(lostRequest); err == nil {
		if response != nil {
			closeBody(t, response)
		}
		t.Fatal("caller unexpectedly received the create response")
	}
	if err := <-forwarded; err != nil {
		t.Fatalf("lost-response proxy: %v", err)
	}
	head := h.request(http.MethodHead, lostKey, nil)
	head.Header.Set("x-amz-checksum-mode", "ENABLED")
	h.sign(head, accessKey, secretKey, nil)
	response = h.do(head)
	if response.StatusCode != http.StatusOK || len(closeBody(t, response)) != 0 {
		t.Fatalf("audit after lost response status=%d", response.StatusCode)
	}
	shaDigest := sha256.Sum256(lostPayload)
	if response.Header.Get("x-amz-checksum-sha256") != base64.StdEncoding.EncodeToString(shaDigest[:]) {
		t.Fatalf("audit after lost response returned wrong checksum: %v", response.Header)
	}
	response = h.do(h.putRequest(lostKey, lostPayload))
	if response.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("retry after lost response status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	wantKeys := []string{key, lostKey}
	for index := 0; index < 5; index++ {
		body := []byte(fmt.Sprintf("pagination-%d", index))
		listedKey := objectKey(body, byte(30+index))
		wantKeys = append(wantKeys, listedKey)
		response = h.do(h.putRequest(listedKey, body))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("pagination fixture status=%d body=%s", response.StatusCode, closeBody(t, response))
		}
		closeBody(t, response)
	}
	sort.Strings(wantKeys)
	gotKeys := listAllPages(t, h, "objects/", 2)
	if !equalStrings(gotKeys, wantKeys) {
		t.Fatalf("paginated listing=%v, want %v", gotKeys, wantKeys)
	}
}

func TestDockerServerRejectsMalformedTruncatedUnauthorizedAndTraversalRequests(t *testing.T) {
	requireDockerIntegration(t)
	buildDockerServer(t)
	h := newDockerHarness(t)
	h.start()

	payload := []byte("body must be complete")
	key := objectKey(payload, 41)
	truncated := h.putRequest(key, payload)
	truncatedStatus := sendTruncatedRequest(t, h, truncated, len(payload)/2)
	if truncatedStatus == http.StatusOK {
		t.Fatal("truncated request succeeded")
	}
	response := h.do(h.request(http.MethodGet, key, nil))
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("truncated request published an object: status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	malformed := "GET /" + testBucket + "/" + key + " HTTP/1.1\r\nHost: localhost:" + h.port + "\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
	if malformedStatus := sendMalformedBytes(t, h, []byte(malformed)); malformedStatus == http.StatusOK {
		t.Fatal("malformed HTTP request succeeded")
	}

	unknownPut := h.putRequest(key, payload)
	h.sign(unknownPut, "unknown-access", secretKey, payload)
	response = h.do(unknownPut)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown credential PUT status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
	badSignature := h.request(http.MethodGet, key, nil)
	authorization := badSignature.Header.Get("Authorization")
	replacement := byte('0')
	if authorization[len(authorization)-1] == replacement {
		replacement = '1'
	}
	badSignature.Header.Set("Authorization", authorization[:len(authorization)-1]+string(replacement))
	response = h.do(badSignature)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("bad signature status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	traversalURL := "https://localhost:" + h.port + "/" + testBucket + "/../" + key
	traversal, err := http.NewRequest(http.MethodPut, traversalURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	addDockerPutHeaders(traversal, payload)
	h.sign(traversal, accessKey, secretKey, payload)
	response = h.do(traversal)
	if response.StatusCode == http.StatusOK {
		t.Fatalf("traversal PUT succeeded: body=%s", closeBody(t, response))
	}
	closeBody(t, response)

	copyRequest := h.putRequest(key, payload)
	copyRequest.Header.Set("x-amz-copy-source", "/"+testBucket+"/source")
	h.sign(copyRequest, accessKey, secretKey, payload)
	response = h.do(copyRequest)
	if response.StatusCode == http.StatusOK {
		t.Fatalf("copy-overwrite request succeeded: body=%s", closeBody(t, response))
	}
	closeBody(t, response)
	multipart, err := http.NewRequest(http.MethodPost, "https://localhost:"+h.port+"/"+testBucket+"/"+key+"?uploads=", nil)
	if err != nil {
		t.Fatal(err)
	}
	h.sign(multipart, accessKey, secretKey, nil)
	response = h.do(multipart)
	if response.StatusCode == http.StatusOK {
		t.Fatalf("multipart request succeeded: body=%s", closeBody(t, response))
	}
	closeBody(t, response)
	deleteRequest := h.request(http.MethodDelete, key, nil)
	response = h.do(deleteRequest)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("writer DELETE status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)

	response = h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid request after rejection matrix status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
}

func TestDockerServerBackendSymlinkAndProcessKillNeverPublish(t *testing.T) {
	requireDockerIntegration(t)
	buildDockerServer(t)

	t.Run("backend symlink", func(t *testing.T) {
		h := newDockerHarness(t)
		run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "--user", "0", "--entrypoint", "/bin/sh", "-v", h.volume+":/data", dockerImage, "-c", "mkdir -p /data/escape && ln -s /data/escape /data/objects && chown -h 65532:65532 /data/objects")
		h.start()
		payload := []byte("must not follow backend symlink")
		key := objectKey(payload, 51)
		response := h.do(h.putRequest(key, payload))
		if response.StatusCode != http.StatusInternalServerError {
			t.Fatalf("symlink PUT status=%d body=%s", response.StatusCode, closeBody(t, response))
		}
		closeBody(t, response)
		if output := run(t, "", "docker", "run", "--rm", "--label", dockerRunLabel, "--entrypoint", "/bin/sh", "-v", h.volume+":/data", dockerImage, "-c", "find /data/escape -mindepth 1 -print"); strings.TrimSpace(output) != "" {
			t.Fatalf("server escaped through backend symlink: %s", output)
		}
	})

	t.Run("SIGKILL during upload", func(t *testing.T) {
		h := newDockerHarness(t)
		h.start()
		payload := bytes.Repeat([]byte("kill-during-upload-"), 4<<20)
		key := objectKey(payload, 52)
		request, err := http.NewRequest(http.MethodPut, "https://localhost:"+h.port+"/"+testBucket+"/"+key, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Body = io.NopCloser(&pacedReader{reader: bytes.NewReader(payload), delay: 2 * time.Millisecond, maximum: 32 << 10})
		request.ContentLength = int64(len(payload))
		addDockerPutHeaders(request, payload)
		h.sign(request, accessKey, secretKey, payload)
		requestError := make(chan error, 1)
		go func() {
			response, err := h.client.Do(request)
			if response != nil {
				_ = response.Body.Close()
			}
			requestError <- err
		}()
		waitForContainerPath(t, h, "/data/.backup-server-internal/uploads", false)
		oldContainer := h.container
		if output, err := exec.Command("docker", "kill", "--signal", "KILL", oldContainer).CombinedOutput(); err != nil {
			t.Fatalf("kill server: %v: %s", err, output)
		}
		select {
		case <-requestError:
		case <-time.After(15 * time.Second):
			t.Fatal("upload client did not observe killed server")
		}
		if output, err := exec.Command("docker", "rm", "-f", oldContainer).CombinedOutput(); err != nil {
			t.Fatalf("remove killed server: %v: %s", err, output)
		}
		h.container = ""
		h.start()
		if containerPathExists(t, h, "/data/"+key) {
			t.Fatal("SIGKILL published a partial final object")
		}
		if containerDirectoryNonempty(t, h, "/data/.backup-server-internal/uploads") {
			t.Fatal("stale upload was not removed on restart")
		}
		response := h.do(h.putRequest(key, payload))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("retry after SIGKILL status=%d body=%s", response.StatusCode, closeBody(t, response))
		}
		closeBody(t, response)
	})
}

func TestDockerServerDiskFullFailureDoesNotPublish(t *testing.T) {
	requireDockerIntegration(t)
	buildDockerServer(t)
	h := newDockerHarness(t)
	h.dataMount = []string{"--tmpfs", "/data:rw,size=1048576,mode=0700,uid=65532,gid=65532"}
	h.start()

	payload := bytes.Repeat([]byte("disk-full"), 256<<10)
	key := objectKey(payload, 61)
	response := h.do(h.putRequest(key, payload))
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("disk-full PUT status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
	if containerPathExists(t, h, "/data/"+key) {
		t.Fatal("disk-full request published an object")
	}
	if containerDirectoryNonempty(t, h, "/data/.backup-server-internal/uploads") {
		t.Fatal("disk-full request left a temporary upload")
	}

	small := []byte("space was reclaimed after failed upload")
	smallKey := objectKey(small, 62)
	response = h.do(h.putRequest(smallKey, small))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("small create after disk-full failure status=%d body=%s", response.StatusCode, closeBody(t, response))
	}
	closeBody(t, response)
}

func lostResponseProxy(t *testing.T, target *dockerHarness) (*httptest.Server, <-chan error) {
	t.Helper()
	forwarded := make(chan error, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		targetURL := *incoming.URL
		targetURL.Scheme = "https"
		targetURL.Host = "localhost:" + target.port
		forward := incoming.Clone(incoming.Context())
		forward.URL = &targetURL
		forward.RequestURI = ""
		forward.Host = incoming.Host
		response, err := target.client.Transport.RoundTrip(forward)
		if err == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				err = readErr
			} else if closeErr != nil {
				err = closeErr
			} else if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("upstream create status %d", response.StatusCode)
			}
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			if err == nil {
				err = fmt.Errorf("proxy response writer cannot hijack")
			}
			forwarded <- err
			return
		}
		connection, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil && err == nil {
			err = hijackErr
		}
		if connection != nil {
			_ = connection.Close()
		}
		forwarded <- err
	}))
	t.Cleanup(proxy.Close)
	return proxy, forwarded
}

func requireDockerIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("BACKUP_DOCKER_TEST") != "1" {
		t.Skip("set BACKUP_DOCKER_TEST=1 to run Docker integration")
	}
}

func buildDockerServer(t *testing.T) {
	t.Helper()
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	ensureDockerImages(t, repoRoot)
}

func addDockerPutHeaders(request *http.Request, body []byte) {
	md5Digest := md5.Sum(body)
	shaDigest := sha256.Sum256(body)
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(md5Digest[:]))
	request.Header.Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(shaDigest[:]))
	request.Header.Set("x-amz-sdk-checksum-algorithm", "SHA256")
}

type listBucketResult struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func listAllPages(t *testing.T, h *dockerHarness, prefix string, maxKeys int) []string {
	t.Helper()
	var result []string
	continuation := ""
	for {
		query := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {fmt.Sprint(maxKeys)}}
		if continuation != "" {
			query.Set("continuation-token", continuation)
		}
		request, err := http.NewRequest(http.MethodGet, "https://localhost:"+h.port+"/"+testBucket+"?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		h.sign(request, accessKey, secretKey, nil)
		response := h.do(request)
		body := closeBody(t, response)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("list status=%d body=%s", response.StatusCode, body)
		}
		var page listBucketResult
		if err := xml.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		for _, object := range page.Contents {
			result = append(result, object.Key)
		}
		if !page.IsTruncated {
			return result
		}
		if page.NextContinuationToken == "" {
			t.Fatal("truncated list omitted continuation token")
		}
		continuation = page.NextContinuationToken
	}
}

func sendTruncatedRequest(t *testing.T, h *dockerHarness, request *http.Request, bodyBytes int) int {
	t.Helper()
	connection := writeRawRequest(t, h, request, bodyBytes)
	defer func() { _ = connection.Close() }()
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return 0
	}
	status := response.StatusCode
	closeBody(t, response)
	return status
}

func writeRawRequest(t *testing.T, h *dockerHarness, request *http.Request, bodyBytes int) *tls.Conn {
	t.Helper()
	var serialized bytes.Buffer
	if err := request.Write(&serialized); err != nil {
		t.Fatal(err)
	}
	wire := serialized.Bytes()
	if bodyBytes >= 0 {
		separator := bytes.Index(wire, []byte("\r\n\r\n"))
		if separator < 0 {
			t.Fatal("serialized HTTP request lacks header terminator")
		}
		bodyStart := separator + 4
		if bodyBytes > len(wire)-bodyStart {
			t.Fatal("requested raw body exceeds serialized body")
		}
		wire = wire[:bodyStart+bodyBytes]
	}
	connection := dialRawTLS(t, h)
	if _, err := connection.Write(wire); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	if bodyBytes >= 0 {
		if err := connection.CloseWrite(); err != nil {
			_ = connection.Close()
			t.Fatal(err)
		}
	}
	return connection
}

func sendMalformedBytes(t *testing.T, h *dockerHarness, wire []byte) int {
	t.Helper()
	connection := dialRawTLS(t, h)
	defer func() { _ = connection.Close() }()
	if _, err := connection.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		return 0
	}
	status := response.StatusCode
	closeBody(t, response)
	return status
}

func dialRawTLS(t *testing.T, h *dockerHarness) *tls.Conn {
	t.Helper()
	transport, ok := h.client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("Docker test client has no TLS configuration")
	}
	config := transport.TLSClientConfig.Clone()
	config.ServerName = "localhost"
	connection, err := tls.Dial("tcp", "127.0.0.1:"+h.port, config)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

type pacedReader struct {
	reader  io.Reader
	delay   time.Duration
	maximum int
}

func (reader *pacedReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		buffer = buffer[:reader.maximum]
	}
	time.Sleep(reader.delay)
	return reader.reader.Read(buffer)
}

func waitForContainerPath(t *testing.T, h *dockerHarness, path string, regular bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		exists := containerPathExists(t, h, path)
		if regular && exists || !regular && containerDirectoryNonempty(t, h, path) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("container path did not reach expected state: %s", path)
}

func containerPathExists(t *testing.T, h *dockerHarness, path string) bool {
	t.Helper()
	return dockerExecStatus(h.container, "test", "-f", path)
}

func containerDirectoryNonempty(t *testing.T, h *dockerHarness, path string) bool {
	t.Helper()
	return dockerExecStatus(h.container, "/bin/sh", "-c", "test -d \"$1\" && test -n \"$(ls -A \"$1\")\"", "sh", path)
}

func dockerExecStatus(container string, arguments ...string) bool {
	command := append([]string{"exec", container}, arguments...)
	return exec.Command("docker", command...).Run() == nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
