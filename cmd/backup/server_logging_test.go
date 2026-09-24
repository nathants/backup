package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLILoggingServerRequestsAndTLSErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BACKUP_SERVER_ACCESS_KEY", "logging-test-access")
	t.Setenv("BACKUP_SERVER_SECRET_KEY", "logging-test-secret")
	t.Setenv("BACKUP_SERVER_SESSION_TOKEN", "")
	// Reuse the standard test server's certificate and trusted client, not an
	// insecure-skip client. Requests below go to the actual CLI server.
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	client := fixture.Client()
	client.Timeout = 5 * time.Second
	fixture.Close()
	defer client.CloseIdleConnections()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(t.TempDir(), "server.crt")
	keyPath := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	var stderr bytes.Buffer
	var status int
	done := make(chan struct{})
	root := t.TempDir()
	go func() {
		status = execute(ctx, []string{"server", "--listen", "127.0.0.1:0", "--data-root", root, "--bucket", "backup-test", "--tls-cert", certificatePath, "--tls-key", keyPath}, writer, &stderr)
		_ = writer.Close()
		close(done)
	}()
	defer func() {
		cancel()
		_ = reader.Close()
		<-done
	}()
	address, err := bufio.NewReader(reader).ReadString('\n')
	if err != nil {
		<-done
		t.Fatalf("server startup: %v; status=%d stderr=%s", err, status, &stderr)
	}
	address = strings.TrimSpace(address)
	request, err := http.NewRequest(http.MethodGet, "https://"+address+"/backup-test/logging-test-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusForbidden || readErr != nil || closeErr != nil {
		t.Fatalf("unauthenticated request: status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, connection); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if status != 0 {
		t.Fatalf("server shutdown failed: %d %s", status, &stderr)
	}
	records := readDebugLogs(t, home)
	disk := recordedStream(records, "stderr")
	if disk != stderr.String() || recordedStream(records, "stdout") != address+"\n" || strings.Contains(disk, "logging-test-secret") {
		t.Fatalf("server log missing output or exposing credentials: %q", disk)
	}
	var requestLogged, handshakeLogged bool
	for _, line := range strings.Split(strings.TrimSpace(disk), "\n") {
		if strings.Contains(line, "http: TLS handshake error") {
			handshakeLogged = true
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("request log is not structured: %v", err)
		}
		if entry["status"] == float64(http.StatusForbidden) && entry["path"] == "/backup-test/[redacted]" {
			requestLogged = true
		}
	}
	if !requestLogged || !handshakeLogged {
		t.Fatalf("missing request or HTTP server diagnostics: %s", disk)
	}
}
