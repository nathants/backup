package s3server

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Server struct {
	Dir       string
	AccessKey string
	SecretKey string
	Region    string
}

func (server *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bucket, key, err := parsePath(r.URL.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidURI", err.Error())
		return
	}

	payloadMode := strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))
	if payloadMode == "" {
		writeError(w, http.StatusBadRequest, "InvalidRequest", "x-amz-content-sha256 required")
		return
	}
	if payloadMode == "UNSIGNED-PAYLOAD" || payloadMode == "STREAMING-UNSIGNED-PAYLOAD-TRAILER" {
		writeError(w, http.StatusForbidden, "AccessDenied", "unsigned payloads are not allowed")
		return
	}

	credential, signature, signedHeaders, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusForbidden, "AccessDenied", err.Error())
		return
	}
	if credential.AccessKey != server.AccessKey {
		writeError(w, http.StatusForbidden, "AccessDenied", "invalid access key")
		return
	}
	if credential.Service != "s3" {
		writeError(w, http.StatusForbidden, "AccessDenied", "invalid service")
		return
	}

	canonicalRequest, err := canonicalRequest(r, signedHeaders, payloadMode)
	if err != nil {
		writeError(w, http.StatusForbidden, "AccessDenied", err.Error())
		return
	}
	stringToSign, err := stringToSign(r, credential.String(), canonicalRequest)
	if err != nil {
		writeError(w, http.StatusForbidden, "AccessDenied", err.Error())
		return
	}
	keyBytes := signingKey(server.SecretKey, credential.Date, credential.Region, credential.Service)
	expectedSignature := hmacHex(keyBytes, stringToSign)
	if signature != expectedSignature {
		writeError(w, http.StatusForbidden, "SignatureDoesNotMatch", "signature mismatch")
		return
	}

	objectPath := filepath.Join(server.Dir, bucket, filepath.FromSlash(key))
	switch r.Method {
	case http.MethodPut:
		if _, err := os.Stat(objectPath); err == nil {
			writeError(w, http.StatusConflict, "KeyAlreadyExists", "object already exists")
			return
		}
		if err := os.MkdirAll(filepath.Dir(objectPath), 0755); err != nil {
			writeError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		file, err := os.Create(objectPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = file.Close() }()

		if err := server.writeBody(r, file, payloadMode, credential, signature); err != nil {
			_ = os.Remove(objectPath)
			writeError(w, http.StatusForbidden, "AccessDenied", err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet, http.MethodHead:
		if payloadMode != emptySHA256 {
			writeError(w, http.StatusForbidden, "AccessDenied", "payload hash must be empty for get/head")
			return
		}
		file, err := os.Open(objectPath)
		if err != nil {
			if os.IsNotExist(err) {
				writeError(w, http.StatusNotFound, "NoSuchKey", "object not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = file.Close() }()
		info, err := file.Stat()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, err = io.Copy(w, file)
		if err != nil {
			return
		}
		return
	case http.MethodDelete:
		writeError(w, http.StatusForbidden, "AccessDenied", "delete is not allowed")
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "unsupported method")
		return
	}
}

func (server *Server) writeBody(r *http.Request, writer io.Writer, payloadMode string, credential credentialScope, seedSignature string) error {
	if payloadMode == streamingPayload {
		return server.writeStreamingBody(r, writer, seedSignature, credential, false)
	}
	if payloadMode == streamingPayloadTrailer {
		return server.writeStreamingBody(r, writer, seedSignature, credential, true)
	}
	hash := sha256.New()
	tee := io.TeeReader(r.Body, hash)
	_, err := io.Copy(writer, tee)
	if err != nil {
		return err
	}
	payloadHash := fmt.Sprintf("%x", hash.Sum(nil))
	if payloadHash != payloadMode {
		return fmt.Errorf("payload hash mismatch")
	}
	return nil
}

func (server *Server) writeStreamingBody(r *http.Request, writer io.Writer, seedSignature string, credential credentialScope, expectTrailer bool) error {
	if r.Header.Get("Content-Encoding") != "aws-chunked" {
		return fmt.Errorf("aws-chunked encoding required")
	}
	decodedLength := int64(-1)
	if value := r.Header.Get("x-amz-decoded-content-length"); value != "" {
		parsed, err := parseInt64(value)
		if err != nil {
			return err
		}
		decodedLength = parsed
	}
	if expectTrailer {
		if r.Header.Get("x-amz-trailer") == "" {
			return fmt.Errorf("x-amz-trailer required")
		}
	}
	signer := chunkSigner{
		SeedSignature: seedSignature,
		SigningKey:    signingKey(server.SecretKey, credential.Date, credential.Region, credential.Service),
		Scope:         credential.String(),
		AmzDate:       r.Header.Get("x-amz-date"),
	}
	decoded, finalSignature, trailers, err := decodeChunks(r.Body, writer, signer)
	if err != nil {
		return fmt.Errorf("stream decode: %w (transferEncoding=%v contentLength=%d)", err, r.TransferEncoding, r.ContentLength)
	}
	if decodedLength >= 0 && decodedLength != decoded {
		return fmt.Errorf("decoded length mismatch")
	}
	if expectTrailer {
		required := r.Header.Get("x-amz-trailer")
		trailerSignature, ok := trailers["x-amz-trailer-signature"]
		if !ok {
			return fmt.Errorf("missing trailer signature")
		}
		trailerPayload, err := trailerPayload(required, trailers)
		if err != nil {
			return err
		}
		expected := trailerSignatureFor(signer, finalSignature, trailerPayload)
		if trailerSignature != expected {
			return fmt.Errorf("trailer signature mismatch")
		}
	} else {
		if len(trailers) != 0 {
			return fmt.Errorf("unexpected trailers")
		}
	}
	return nil
}

func parsePath(requestPath string) (string, string, error) {
	path := strings.TrimPrefix(requestPath, "/")
	if path == "" {
		return "", "", fmt.Errorf("missing bucket")
	}
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("missing key")
	}
	bucket := parts[0]
	key := parts[1]
	if strings.Contains(key, "..") {
		return "", "", fmt.Errorf("invalid key")
	}
	if bucket == "" || key == "" {
		return "", "", fmt.Errorf("invalid path")
	}
	return bucket, key, nil
}
