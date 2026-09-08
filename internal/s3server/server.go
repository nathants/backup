package s3server

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const (
	internalDirectory  = ".backup-server-internal"
	temporaryDirectory = "uploads"
	lockFilename       = "lock"
	maximumKeyBytes    = 1024
	maximumIndexedKeys = 1_000_000
	defaultMaxObject   = int64(1 << 30) // 1 GiB, matching the production client's maximum ordinary part size.
)

var randomSource io.Reader = rand.Reader

type Role string

const (
	RoleWriter Role = "writer"
	RoleReader Role = "reader"
)

type Credential struct {
	SecretKey    string
	SessionToken string
	Role         Role
}

type Config struct {
	Root              string
	Bucket            string
	Prefix            string
	Region            string
	Credentials       map[string]Credential
	MaximumObjectSize int64
	MaximumClockSkew  time.Duration
	Now               func() time.Time
	Logger            *slog.Logger
}

type objectListingIndex struct {
	mutex       sync.Mutex
	sorted      []listContent
	pending     []listContent
	overflow    bool
	scanErr     error
	inspections uint64
}

type Server struct {
	config  Config
	rootFD  int
	tempFD  int
	lock    *os.File
	listing map[string]*objectListingIndex

	closeOnce sync.Once
	closeErr  error
}

func Open(config Config) (*Server, error) {
	if config.Root == "" || config.Bucket == "" || config.Region == "" {
		return nil, fmt.Errorf("server root, bucket, and region are required")
	}
	if err := validateBucket(config.Bucket); err != nil {
		return nil, err
	}
	if config.Prefix != "" {
		if len(config.Prefix) > maximumKeyBytes || !utf8StringWithoutControls(config.Prefix) || strings.HasPrefix(config.Prefix, "/") || strings.HasSuffix(config.Prefix, "/") || path.Clean(config.Prefix) != config.Prefix {
			return nil, fmt.Errorf("server prefix is not canonical")
		}
		for _, component := range strings.Split(config.Prefix, "/") {
			if component == "" || component == "." || component == ".." || component == internalDirectory {
				return nil, fmt.Errorf("server prefix has an invalid component")
			}
		}
	}
	if len(config.Credentials) == 0 {
		return nil, fmt.Errorf("at least one server credential is required")
	}
	for accessKey, credential := range config.Credentials {
		if accessKey == "" || credential.SecretKey == "" {
			return nil, fmt.Errorf("access and secret keys must be nonempty")
		}
		if credential.Role != RoleWriter && credential.Role != RoleReader {
			return nil, fmt.Errorf("credential %q has invalid role %q", accessKey, credential.Role)
		}
	}
	if config.MaximumObjectSize == 0 {
		config.MaximumObjectSize = defaultMaxObject
	}
	if config.MaximumObjectSize < 1 {
		return nil, fmt.Errorf("maximum object size must be positive")
	}
	if config.MaximumClockSkew == 0 {
		config.MaximumClockSkew = 15 * time.Minute
	}
	if config.MaximumClockSkew < time.Second {
		return nil, fmt.Errorf("maximum clock skew must be at least one second")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if info, err := os.Lstat(config.Root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("data root already exists and is not a directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(config.Root, 0o700); err != nil {
			return nil, fmt.Errorf("create data root: %w", err)
		}
	} else {
		return nil, fmt.Errorf("inspect data root: %w", err)
	}
	rootFD, err := unix.Open(config.Root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open data root: %w", err)
	}
	if err := unix.Fchmod(rootFD, 0o700); err != nil {
		unix.Close(rootFD)
		return nil, fmt.Errorf("set data-root mode: %w", err)
	}
	server := &Server{
		config: config, rootFD: rootFD, tempFD: -1,
		listing: map[string]*objectListingIndex{
			"objects": {}, "metadata/parts": {}, "metadata/manifests": {},
		},
	}
	failed := true
	defer func() {
		if failed {
			_ = server.Close()
		}
	}()
	internalFD, err := openOrCreateDirectory(rootFD, internalDirectory, 0o700)
	if err != nil {
		return nil, fmt.Errorf("open internal directory: %w", err)
	}
	defer unix.Close(internalFD)
	lockFD, err := unix.Openat(internalFD, lockFilename, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open server lock: %w", err)
	}
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || lockStat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(lockFD)
		if err != nil {
			return nil, fmt.Errorf("inspect server lock: %w", err)
		}
		return nil, fmt.Errorf("server lock must be a regular file")
	}
	if err := unix.Fchmod(lockFD, 0o600); err != nil {
		_ = unix.Close(lockFD)
		return nil, fmt.Errorf("set server-lock mode: %w", err)
	}
	server.lock = os.NewFile(uintptr(lockFD), lockFilename)
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("data root is already locked by another server: %w", err)
	}
	tempFD, err := openOrCreateDirectory(internalFD, temporaryDirectory, 0o700)
	if err != nil {
		return nil, fmt.Errorf("open upload temp directory: %w", err)
	}
	server.tempFD = tempFD
	if err := cleanupTemporaryFiles(tempFD); err != nil {
		return nil, fmt.Errorf("clean stale uploads: %w", err)
	}
	server.rebuildListingIndices()
	failed = false
	return server, nil
}

func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		var errs []error
		if server.tempFD >= 0 {
			if err := unix.Close(server.tempFD); err != nil {
				errs = append(errs, err)
			}
			server.tempFD = -1
		}
		if server.lock != nil {
			if err := unix.Flock(int(server.lock.Fd()), unix.LOCK_UN); err != nil {
				errs = append(errs, err)
			}
			if err := server.lock.Close(); err != nil {
				errs = append(errs, err)
			}
			server.lock = nil
		}
		if server.rootFD >= 0 {
			if err := unix.Close(server.rootFD); err != nil {
				errs = append(errs, err)
			}
			server.rootFD = -1
		}
		server.closeErr = errors.Join(errs...)
	})
	return server.closeErr
}

type trackedResponseWriter struct {
	http.ResponseWriter
	committed bool
}

func (writer *trackedResponseWriter) WriteHeader(status int) {
	if writer.committed {
		return
	}
	writer.committed = true
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *trackedResponseWriter) Write(data []byte) (int, error) {
	if !writer.committed {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

func (writer *trackedResponseWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	tracked := &trackedResponseWriter{ResponseWriter: writer}
	requestID, err := randomHex(16)
	if err != nil {
		server.config.Logger.Error("request ID generation failed", "error", err)
		writeError(tracked, http.StatusInternalServerError, "InternalError", "internal server error", "unavailable", request.URL.EscapedPath())
		return
	}
	tracked.Header().Set("x-amz-request-id", requestID)
	status, code, message := server.handle(tracked, request)
	if status >= http.StatusInternalServerError {
		server.config.Logger.Error("request failed", "request_id", requestID, "method", request.Method, "path", request.URL.EscapedPath(), "status", status, "code", code, "message", message)
	} else {
		server.config.Logger.Info("request", "request_id", requestID, "method", request.Method, "path", request.URL.EscapedPath(), "status", status, "code", code)
	}
	if status != 0 && !tracked.committed {
		writeError(tracked, status, code, message, requestID, request.URL.EscapedPath())
	}
}

func (server *Server) handle(writer http.ResponseWriter, request *http.Request) (int, string, string) {
	if request.URL.Scheme != "" || request.URL.Host != "" {
		return http.StatusBadRequest, "InvalidRequest", "absolute request targets are unsupported"
	}
	if request.Header.Get("x-amz-content-sha256") == "" {
		return http.StatusBadRequest, "InvalidRequest", "x-amz-content-sha256 is required"
	}
	if !isLowerHex(request.Header.Get("x-amz-content-sha256"), sha256.Size*2) {
		return http.StatusForbidden, "AccessDenied", "only fixed signed SHA-256 payloads are accepted"
	}
	authorization, err := parseAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		return http.StatusForbidden, "AccessDenied", err.Error()
	}
	credential, ok := server.config.Credentials[authorization.Scope.AccessKey]
	if !ok {
		return http.StatusForbidden, "InvalidAccessKeyId", "unknown access key"
	}
	if authorization.Scope.Region != server.config.Region || authorization.Scope.Service != "s3" {
		return http.StatusForbidden, "AuthorizationHeaderMalformed", "credential scope has the wrong region or service"
	}
	if err := validateRequestDate(request, authorization, server.config.Now().UTC(), server.config.MaximumClockSkew); err != nil {
		return http.StatusForbidden, "RequestTimeTooSkewed", err.Error()
	}
	if err := requireSecurityHeadersSigned(request, authorization); err != nil {
		return http.StatusForbidden, "AccessDenied", err.Error()
	}
	if credential.SessionToken != "" {
		if request.Header.Get("x-amz-security-token") != credential.SessionToken {
			return http.StatusForbidden, "InvalidToken", "session token is missing or invalid"
		}
	} else if request.Header.Get("x-amz-security-token") != "" {
		return http.StatusForbidden, "InvalidToken", "this credential does not use a session token"
	}
	if err := rejectUnknownAWSHeaders(request); err != nil {
		return http.StatusBadRequest, "InvalidRequest", err.Error()
	}
	if err := verifySignature(request, authorization, credential.SecretKey); err != nil {
		return http.StatusForbidden, "SignatureDoesNotMatch", err.Error()
	}
	if len(request.TransferEncoding) != 0 || request.Header.Get("Content-Encoding") != "" {
		return http.StatusBadRequest, "InvalidRequest", "transfer and content encodings are unsupported"
	}
	if request.Method != http.MethodPut && (request.ContentLength != 0 || request.Header.Get("x-amz-content-sha256") != emptySHA256) {
		return http.StatusBadRequest, "InvalidRequest", "non-PUT requests require an empty fixed payload"
	}

	bucket, key, list, err := parseRequestTarget(request)
	if err != nil {
		return http.StatusBadRequest, "InvalidURI", err.Error()
	}
	if bucket != server.config.Bucket {
		return http.StatusNotFound, "NoSuchBucket", "bucket does not exist"
	}
	if list {
		if credential.Role != RoleReader {
			return http.StatusForbidden, "AccessDenied", "reader credential required"
		}
		if err := server.listObjects(writer, request); err != nil {
			return statusForError(err)
		}
		return 0, "", ""
	}
	key, err = server.logicalKey(key)
	if err != nil {
		return http.StatusBadRequest, "InvalidURI", err.Error()
	}

	switch request.Method {
	case http.MethodPut:
		if credential.Role != RoleWriter {
			return http.StatusForbidden, "AccessDenied", "writer credential required"
		}
		if err := server.putObject(request.Context(), writer, request, key); err != nil {
			return statusForError(err)
		}
	case http.MethodGet:
		if credential.Role != RoleReader {
			return http.StatusForbidden, "AccessDenied", "reader credential required"
		}
		if err := server.getObject(request.Context(), writer, key); err != nil {
			return statusForError(err)
		}
	case http.MethodHead:
		if credential.Role != RoleReader {
			return http.StatusForbidden, "AccessDenied", "reader credential required"
		}
		if err := server.headObject(request.Context(), writer, request, key); err != nil {
			return statusForError(err)
		}
	case http.MethodDelete:
		return http.StatusForbidden, "AccessDenied", "delete is not allowed"
	default:
		return http.StatusMethodNotAllowed, "MethodNotAllowed", "unsupported method"
	}
	return 0, "", ""
}

type requestError struct {
	status  int
	code    string
	message string
}

func (err *requestError) Error() string { return err.message }

func statusForError(err error) (int, string, string) {
	var requestErr *requestError
	if errors.As(err, &requestErr) {
		return requestErr.status, requestErr.code, requestErr.message
	}
	return http.StatusInternalServerError, "InternalError", "internal server error"
}

func requestFailure(status int, code, message string) error {
	return &requestError{status: status, code: code, message: message}
}

func (server *Server) putObject(ctx context.Context, writer http.ResponseWriter, request *http.Request, key string) error {
	if request.ContentLength <= 0 {
		return requestFailure(http.StatusBadRequest, "InvalidRequest", "PUT requires a nonzero fixed Content-Length")
	}
	if request.ContentLength > server.config.MaximumObjectSize {
		return requestFailure(http.StatusRequestEntityTooLarge, "EntityTooLarge", "object exceeds server size limit")
	}
	if request.Header.Get("If-None-Match") != "*" {
		return requestFailure(http.StatusPreconditionFailed, "PreconditionFailed", "PUT requires If-None-Match: *")
	}
	contentMD5, err := decodeChecksum(request.Header.Get("Content-MD5"), md5.Size, "Content-MD5")
	if err != nil {
		return requestFailure(http.StatusBadRequest, "InvalidDigest", err.Error())
	}
	checksumSHA256, err := decodeChecksum(request.Header.Get("x-amz-checksum-sha256"), sha256.Size, "x-amz-checksum-sha256")
	if err != nil {
		return requestFailure(http.StatusBadRequest, "InvalidRequest", err.Error())
	}
	payloadSHA256, _ := hex.DecodeString(request.Header.Get("x-amz-content-sha256"))
	expectedPartHash, err := keyContentHash(key)
	if err != nil {
		return requestFailure(http.StatusBadRequest, "InvalidURI", err.Error())
	}

	tempName, tempFile, err := createTemporaryFile(server.tempFD)
	if err != nil {
		return fmt.Errorf("create upload temp: %w", err)
	}
	tempPublished := false
	defer func() {
		_ = tempFile.Close()
		if !tempPublished {
			_ = unix.Unlinkat(server.tempFD, tempName, 0)
		}
	}()
	blakeHash, _ := blake2b.New512(nil)
	shaHash := sha256.New()
	md5Hash := md5.New()
	tempWriter := &errorTrackingWriter{writer: tempFile}
	limited := &io.LimitedReader{R: request.Body, N: request.ContentLength + 1}
	written, copyErr := io.Copy(io.MultiWriter(tempWriter, blakeHash, shaHash, md5Hash), limited)
	if tempWriter.err != nil {
		return fmt.Errorf("write upload temp: %w", tempWriter.err)
	}
	if copyErr != nil {
		return requestFailure(http.StatusBadRequest, "IncompleteBody", "request body could not be read completely")
	}
	if ctx.Err() != nil {
		return requestFailure(http.StatusBadRequest, "RequestTimeout", "request was canceled")
	}
	if written != request.ContentLength || limited.N != 1 {
		return requestFailure(http.StatusBadRequest, "IncompleteBody", "request body length disagrees with Content-Length")
	}
	partHash := blakeHash.Sum(nil)
	shaDigest := shaHash.Sum(nil)
	md5Digest := md5Hash.Sum(nil)
	if !equalBytes(partHash, expectedPartHash) {
		return requestFailure(http.StatusBadRequest, "BadDigest", "object bytes do not match the hash embedded in the key")
	}
	if !equalBytes(shaDigest, payloadSHA256) || !equalBytes(shaDigest, checksumSHA256) {
		return requestFailure(http.StatusBadRequest, "BadDigest", "SHA-256 checksum mismatch")
	}
	if !equalBytes(md5Digest, contentMD5) {
		return requestFailure(http.StatusBadRequest, "BadDigest", "MD5 checksum mismatch")
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("fsync upload temp: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close upload temp: %w", err)
	}
	if err := server.installTemporary(tempName, key); err != nil {
		// Link publication precedes directory fsync and temp cleanup. If either
		// later step fails, the key is already visible and must enter the live
		// listing index even though the response is ambiguous.
		if file, info, openErr := server.openObject(key); openErr == nil {
			_ = file.Close()
			server.addListingObject(key, info.Size())
		}
		if errors.Is(err, unix.EEXIST) {
			return requestFailure(http.StatusPreconditionFailed, "PreconditionFailed", "object key already exists")
		}
		return fmt.Errorf("install object: %w", err)
	}
	server.addListingObject(key, request.ContentLength)
	tempPublished = true
	writer.Header().Set("ETag", `"`+hex.EncodeToString(md5Digest)+`"`)
	writer.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(shaDigest))
	writer.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	writer.WriteHeader(http.StatusOK)
	return nil
}

func (server *Server) installTemporary(tempName, key string) error {
	components, err := keyComponents(key)
	if err != nil {
		return err
	}
	parentFD, err := server.ensureObjectParent(components[:len(components)-1])
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	leaf := components[len(components)-1]
	if err := unix.Linkat(server.tempFD, tempName, parentFD, leaf, 0); err != nil {
		return err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return err
	}
	if err := unix.Unlinkat(server.tempFD, tempName, 0); err != nil {
		return err
	}
	return unix.Fsync(server.tempFD)
}

func (server *Server) getObject(ctx context.Context, writer http.ResponseWriter, key string) error {
	file, info, err := server.openObject(key)
	if err != nil {
		return err
	}
	defer file.Close()
	writer.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.WriteHeader(http.StatusOK)
	_, err = io.Copy(writer, &contextReader{ctx: ctx, reader: file})
	return err
}

func (server *Server) headObject(ctx context.Context, writer http.ResponseWriter, request *http.Request, key string) error {
	file, info, err := server.openObject(key)
	if err != nil {
		return err
	}
	defer file.Close()
	mode := request.Header.Get("x-amz-checksum-mode")
	if mode != "" && mode != "ENABLED" {
		return requestFailure(http.StatusBadRequest, "InvalidRequest", "x-amz-checksum-mode must be ENABLED")
	}
	if mode == "ENABLED" {
		expectedHash, keyErr := keyContentHash(key)
		if keyErr != nil {
			return requestFailure(http.StatusBadRequest, "InvalidURI", keyErr.Error())
		}
		blakeHash, _ := blake2b.New512(nil)
		shaHash := sha256.New()
		md5Hash := md5.New()
		count, copyErr := io.Copy(io.MultiWriter(blakeHash, shaHash, md5Hash), &contextReader{ctx: ctx, reader: file})
		if copyErr != nil {
			return fmt.Errorf("verify object: %w", copyErr)
		}
		if count != info.Size() || !equalBytes(blakeHash.Sum(nil), expectedHash) {
			return requestFailure(http.StatusInternalServerError, "ObjectCorrupt", "stored object failed content verification")
		}
		writer.Header().Set("x-amz-checksum-sha256", base64.StdEncoding.EncodeToString(shaHash.Sum(nil)))
		writer.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		writer.Header().Set("ETag", `"`+hex.EncodeToString(md5Hash.Sum(nil))+`"`)
	}
	writer.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	writer.WriteHeader(http.StatusOK)
	return nil
}

func (server *Server) openObject(key string) (*os.File, os.FileInfo, error) {
	components, err := keyComponents(key)
	if err != nil {
		return nil, nil, requestFailure(http.StatusBadRequest, "InvalidURI", err.Error())
	}
	currentFD, err := unix.Dup(server.rootFD)
	if err != nil {
		return nil, nil, err
	}
	for _, component := range components[:len(components)-1] {
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(currentFD)
		if openErr != nil {
			if errors.Is(openErr, unix.ENOENT) {
				return nil, nil, requestFailure(http.StatusNotFound, "NoSuchKey", "object does not exist")
			}
			return nil, nil, openErr
		}
		currentFD = nextFD
	}
	leaf := components[len(components)-1]
	objectFD, openErr := unix.Openat(currentFD, leaf, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	unix.Close(currentFD)
	if openErr != nil {
		if errors.Is(openErr, unix.ENOENT) {
			return nil, nil, requestFailure(http.StatusNotFound, "NoSuchKey", "object does not exist")
		}
		return nil, nil, openErr
	}
	file := os.NewFile(uintptr(objectFD), leaf)
	info, statErr := file.Stat()
	if statErr != nil {
		file.Close()
		return nil, nil, statErr
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, requestFailure(http.StatusInternalServerError, "InvalidObjectState", "stored object is not a regular file")
	}
	return file, info, nil
}

func (server *Server) ensureObjectParent(components []string) (int, error) {
	currentFD, err := unix.Dup(server.rootFD)
	if err != nil {
		return -1, err
	}
	for _, component := range components {
		nextFD, openErr := openOrCreateDirectory(currentFD, component, 0o700)
		unix.Close(currentFD)
		if openErr != nil {
			return -1, openErr
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func openOrCreateDirectory(parentFD int, name string, mode uint32) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, err
	}
	if err := unix.Mkdirat(parentFD, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	if err := unix.Fsync(parentFD); err != nil {
		return -1, err
	}
	return unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func createTemporaryFile(directoryFD int) (string, *os.File, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name, err := randomHex(32)
		if err != nil {
			return "", nil, err
		}
		fd, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, os.NewFile(uintptr(fd), name), nil
	}
	return "", nil, fmt.Errorf("could not allocate a unique temporary filename")
}

func cleanupTemporaryFiles(directoryFD int) error {
	copyFD, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(copyFD), temporaryDirectory)
	names, err := directory.Readdirnames(-1)
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	for _, name := range names {
		var stat unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("unexpected non-regular stale upload %q", name)
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(directoryFD)
}

func parseRequestTarget(request *http.Request) (bucket, key string, list bool, err error) {
	if request.URL.Path == "" || request.URL.Path[0] != '/' {
		return "", "", false, fmt.Errorf("path-style bucket URL required")
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "2" {
		if err := validateBucket(parts[0]); err != nil {
			return "", "", false, err
		}
		return parts[0], "", true, nil
	}
	if len(parts) < 2 || parts[0] == "" {
		return "", "", false, fmt.Errorf("bucket and object key are required")
	}
	if err := validateBucket(parts[0]); err != nil {
		return "", "", false, err
	}
	key = strings.Join(parts[1:], "/")
	if _, err := rawKeyComponents(key); err != nil {
		return "", "", false, err
	}
	if request.URL.RawQuery != "" {
		query := request.URL.Query()
		if len(query) != 1 || len(query["x-id"]) != 1 || query.Get("x-id") != operationID(request.Method) {
			return "", "", false, fmt.Errorf("object operations contain unsupported query parameters")
		}
	}
	return parts[0], key, false, nil
}

func operationID(method string) string {
	switch method {
	case http.MethodPut:
		return "PutObject"
	case http.MethodGet:
		return "GetObject"
	case http.MethodHead:
		return "HeadObject"
	case http.MethodDelete:
		return "DeleteObject"
	default:
		return ""
	}
}

func validateBucket(bucket string) error {
	if len(bucket) < 3 || len(bucket) > 63 {
		return fmt.Errorf("bucket name length is invalid")
	}
	for index, char := range []byte(bucket) {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.') {
			return fmt.Errorf("bucket name contains invalid characters")
		}
		if index == 0 || index == len(bucket)-1 {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
				return fmt.Errorf("bucket name has an invalid edge character")
			}
		}
	}
	if strings.Contains(bucket, "..") {
		return fmt.Errorf("bucket name contains adjacent dots")
	}
	return nil
}

func rawKeyComponents(key string) ([]string, error) {
	if key == "" || len(key) > maximumKeyBytes || !utf8StringWithoutControls(key) {
		return nil, fmt.Errorf("invalid object key")
	}
	components := strings.Split(key, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." || component == internalDirectory {
			return nil, fmt.Errorf("invalid object-key component")
		}
	}
	return components, nil
}

func keyComponents(key string) ([]string, error) {
	components, err := rawKeyComponents(key)
	if err != nil {
		return nil, err
	}
	if _, err := keyContentHash(key); err != nil {
		return nil, err
	}
	return components, nil
}

func (server *Server) logicalKey(wireKey string) (string, error) {
	logical := wireKey
	if server.config.Prefix != "" {
		prefix := server.config.Prefix + "/"
		if !strings.HasPrefix(wireKey, prefix) {
			return "", fmt.Errorf("object key is outside the configured prefix")
		}
		logical = strings.TrimPrefix(wireKey, prefix)
	}
	if _, err := keyComponents(logical); err != nil {
		return "", err
	}
	return logical, nil
}

func (server *Server) wireKey(logical string) string {
	if server.config.Prefix == "" {
		return logical
	}
	return server.config.Prefix + "/" + logical
}

func keyContentHash(key string) ([]byte, error) {
	parts := strings.Split(key, "/")
	var hash string
	switch {
	case len(parts) == 3 && parts[0] == "objects" && len(parts[2]) == 32:
		hash = parts[1]
	case len(parts) == 4 && parts[0] == "metadata" && parts[1] == "parts" && len(parts[3]) == 32:
		hash = parts[2]
	case len(parts) == 5 && parts[0] == "metadata" && parts[1] == "manifests" && len(parts[2]) == 64 && len(parts[4]) == 32:
		hash = parts[3]
	default:
		return nil, fmt.Errorf("object key is outside the backup namespace")
	}
	if !isLowerHex(hash, blake2b.Size*2) {
		return nil, fmt.Errorf("object key has an invalid BLAKE2b hash")
	}
	for _, id := range []string{parts[len(parts)-1]} {
		if !isLowerHex(id, 32) {
			return nil, fmt.Errorf("object key has an invalid object ID")
		}
	}
	if parts[0] == "metadata" && parts[1] == "manifests" && !isLowerHex(parts[2], 64) {
		return nil, fmt.Errorf("manifest key has an invalid tip commit")
	}
	return hex.DecodeString(hash)
}

func rejectUnknownAWSHeaders(request *http.Request) error {
	allowed := map[string]struct{}{
		"x-amz-content-sha256": {}, "x-amz-date": {}, "x-amz-security-token": {},
		"x-amz-checksum-sha256": {}, "x-amz-checksum-mode": {}, "x-amz-sdk-checksum-algorithm": {},
		"x-amz-user-agent": {},
	}
	for name := range request.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			if _, ok := allowed[lower]; !ok {
				return fmt.Errorf("unsupported AWS header %q", lower)
			}
		}
	}
	if request.Header.Get("x-amz-sdk-checksum-algorithm") != "" && request.Header.Get("x-amz-sdk-checksum-algorithm") != "SHA256" {
		return fmt.Errorf("x-amz-sdk-checksum-algorithm must be SHA256")
	}
	return nil
}

func decodeChecksum(value string, size int, label string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", label)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not canonical Base64 for a %d-byte digest", label, size)
	}
	return decoded, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func randomHex(bytesCount int) (string, error) {
	if bytesCount < 1 || bytesCount > 1024 {
		return "", fmt.Errorf("invalid random byte count")
	}
	data := make([]byte, bytesCount)
	if _, err := io.ReadFull(randomSource, data); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func utf8StringWithoutControls(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

type errorTrackingWriter struct {
	writer io.Writer
	err    error
}

func (writer *errorTrackingWriter) Write(data []byte) (int, error) {
	count, err := writer.writer.Write(data)
	if err != nil && writer.err == nil {
		writer.err = err
	}
	return count, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

type listResult struct {
	XMLName               xml.Name      `xml:"ListBucketResult"`
	Xmlns                 string        `xml:"xmlns,attr"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	KeyCount              int           `xml:"KeyCount"`
	MaxKeys               int           `xml:"MaxKeys"`
	IsTruncated           bool          `xml:"IsTruncated"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	EncodingType          string        `xml:"EncodingType,omitempty"`
	Contents              []listContent `xml:"Contents"`
}

type listContent struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

func (server *Server) listObjects(writer http.ResponseWriter, request *http.Request) error {
	query := request.URL.Query()
	allowed := map[string]bool{"list-type": true, "prefix": true, "continuation-token": true, "max-keys": true, "encoding-type": true}
	for name, values := range query {
		if !allowed[name] || len(values) != 1 {
			return requestFailure(http.StatusBadRequest, "InvalidArgument", "unsupported or repeated list parameter")
		}
	}
	if query.Get("list-type") != "2" {
		return requestFailure(http.StatusBadRequest, "InvalidArgument", "list-type must be 2")
	}
	prefix := query.Get("prefix")
	wirePrefix := prefix
	if server.config.Prefix != "" {
		configured := server.config.Prefix + "/"
		if !strings.HasPrefix(prefix, configured) {
			return requestFailure(http.StatusBadRequest, "InvalidArgument", "list prefix is outside the configured server prefix")
		}
		prefix = strings.TrimPrefix(prefix, configured)
	}
	if len(prefix) > maximumKeyBytes || !utf8StringWithoutControls(prefix) {
		return requestFailure(http.StatusBadRequest, "InvalidArgument", "invalid prefix")
	}
	maxKeys := 1000
	if text := query.Get("max-keys"); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > 1000 || strconv.Itoa(parsed) != text {
			return requestFailure(http.StatusBadRequest, "InvalidArgument", "max-keys must be a canonical integer from 1 through 1000")
		}
		maxKeys = parsed
	}
	encodingType := query.Get("encoding-type")
	if encodingType != "" && encodingType != "url" {
		return requestFailure(http.StatusBadRequest, "InvalidArgument", "encoding-type must be url")
	}
	startAfter := ""
	if token := query.Get("continuation-token"); token != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
		if err != nil || len(decoded) > maximumKeyBytes || !utf8StringWithoutControls(string(decoded)) {
			return requestFailure(http.StatusBadRequest, "InvalidArgument", "invalid continuation token")
		}
		startAfter = string(decoded)
	}
	selected, err := server.walkObjects(request.Context(), prefix, startAfter, maxKeys+1)
	if err != nil {
		return err
	}
	truncated := len(selected) > maxKeys
	if truncated {
		selected = selected[:maxKeys]
	}
	wireSelected := make([]listContent, len(selected))
	for index, object := range selected {
		wireSelected[index] = listContent{Key: server.wireKey(object.Key), Size: object.Size}
	}
	result := listResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: server.config.Bucket, Prefix: wirePrefix, KeyCount: len(wireSelected), MaxKeys: maxKeys, IsTruncated: truncated, Contents: wireSelected}
	if truncated {
		lastKey := selected[len(selected)-1].Key
		result.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(lastKey))
	}
	if encodingType == "url" {
		result.EncodingType = "url"
		result.Prefix = awsEncode(wirePrefix)
		for index := range result.Contents {
			result.Contents[index].Key = awsEncode(result.Contents[index].Key)
		}
	}
	data, err := xml.Marshal(result)
	if err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/xml")
	writer.Header().Set("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(data)
	return err
}

var listingNamespaceNames = [...]string{"objects", "metadata/parts", "metadata/manifests"}

func listingNamespace(key string) (string, bool) {
	switch {
	case strings.HasPrefix(key, "objects/"):
		return "objects", true
	case strings.HasPrefix(key, "metadata/parts/"):
		return "metadata/parts", true
	case strings.HasPrefix(key, "metadata/manifests/"):
		return "metadata/manifests", true
	default:
		return "", false
	}
}

func listingNamespaceMatches(namespace, prefix string) bool {
	root := namespace + "/"
	return strings.HasPrefix(root, prefix) || strings.HasPrefix(prefix, root)
}

func (server *Server) rebuildListingIndices() {
	for _, namespace := range listingNamespaceNames {
		entries, inspections, scanErr := server.scanListingNamespace(namespace)
		index := server.listing[namespace]
		index.mutex.Lock()
		index.sorted = entries
		index.pending = nil
		index.overflow = len(entries) > maximumIndexedKeys
		if index.overflow {
			index.sorted = nil
		}
		index.scanErr = scanErr
		index.inspections += inspections
		index.mutex.Unlock()
	}
}

func (server *Server) scanListingNamespace(namespace string) ([]listContent, uint64, error) {
	components := strings.Split(namespace, "/")
	currentFD, err := unix.Dup(server.rootFD)
	if err != nil {
		return nil, 0, err
	}
	for _, component := range components {
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(currentFD)
		if errors.Is(openErr, unix.ENOENT) {
			return []listContent{}, 0, nil
		}
		if openErr != nil {
			return nil, 0, openErr
		}
		currentFD = nextFD
	}
	defer unix.Close(currentFD)
	entries := make([]listContent, 0)
	var inspections uint64
	var walk func(int, string) error
	walk = func(directoryFD int, keyPrefix string) error {
		copyFD, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(copyFD), keyPrefix)
		for {
			children, readErr := directory.ReadDir(256)
			for _, child := range children {
				inspections++
				key := keyPrefix + "/" + child.Name()
				var stat unix.Stat_t
				if err := unix.Fstatat(directoryFD, child.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					_ = directory.Close()
					return err
				}
				switch stat.Mode & unix.S_IFMT {
				case unix.S_IFDIR:
					childFD, err := unix.Openat(directoryFD, child.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
					if err != nil {
						_ = directory.Close()
						return err
					}
					walkErr := walk(childFD, key)
					closeErr := unix.Close(childFD)
					if walkErr != nil || closeErr != nil {
						_ = directory.Close()
						return errors.Join(walkErr, closeErr)
					}
				case unix.S_IFREG:
					if _, err := keyContentHash(key); err != nil {
						_ = directory.Close()
						return fmt.Errorf("unexpected regular file outside object namespace %q", key)
					}
					if len(entries) <= maximumIndexedKeys {
						entries = append(entries, listContent{Key: key, Size: stat.Size})
					}
				default:
					_ = directory.Close()
					return fmt.Errorf("unexpected backend entry type at %q", key)
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = directory.Close()
				return readErr
			}
		}
		return directory.Close()
	}
	err = walk(currentFD, namespace)
	sort.Slice(entries, func(left, right int) bool { return entries[left].Key < entries[right].Key })
	return entries, inspections, err
}

func (server *Server) addListingObject(key string, size int64) {
	namespace, ok := listingNamespace(key)
	if !ok {
		return
	}
	index := server.listing[namespace]
	index.mutex.Lock()
	defer index.mutex.Unlock()
	if index.overflow {
		return
	}
	if len(index.sorted)+len(index.pending) >= maximumIndexedKeys {
		index.sorted = mergeListingEntries(index.sorted, index.pending)
		index.pending = nil
		position := sort.Search(len(index.sorted), func(position int) bool { return index.sorted[position].Key >= key })
		if position < len(index.sorted) && index.sorted[position].Key == key {
			return
		}
		if len(index.sorted) >= maximumIndexedKeys {
			index.sorted, index.overflow = nil, true
			return
		}
	}
	index.pending = append(index.pending, listContent{Key: key, Size: size})
}

func mergeListingEntries(sorted, pending []listContent) []listContent {
	sort.Slice(pending, func(left, right int) bool { return pending[left].Key < pending[right].Key })
	if len(sorted) == 0 {
		write := 0
		for _, entry := range pending {
			if write == 0 || pending[write-1].Key != entry.Key {
				pending[write] = entry
				write++
			}
		}
		return pending[:write]
	}
	merged := make([]listContent, 0, len(sorted)+len(pending))
	left, right := 0, 0
	for left < len(sorted) || right < len(pending) {
		var next listContent
		switch {
		case right == len(pending), left < len(sorted) && sorted[left].Key < pending[right].Key:
			next = sorted[left]
			left++
		case left == len(sorted), pending[right].Key < sorted[left].Key:
			next = pending[right]
			right++
		default:
			next = sorted[left]
			left++
			right++
		}
		if len(merged) == 0 || merged[len(merged)-1].Key != next.Key {
			merged = append(merged, next)
		}
	}
	return merged
}

func (index *objectListingIndex) selectObjects(ctx context.Context, matchPrefix, startAfter string, limit int) ([]listContent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	index.mutex.Lock()
	defer index.mutex.Unlock()
	if index.scanErr != nil {
		return nil, index.scanErr
	}
	if index.overflow {
		return nil, fmt.Errorf("object namespace exceeds the %d-key listing ceiling", maximumIndexedKeys)
	}
	if len(index.pending) != 0 {
		index.sorted = mergeListingEntries(index.sorted, index.pending)
		index.pending = nil
	}
	first := sort.Search(len(index.sorted), func(position int) bool {
		key := index.sorted[position].Key
		return key > startAfter && key >= matchPrefix
	})
	selected := make([]listContent, 0, limit)
	for position := first; position < len(index.sorted) && len(selected) < limit; position++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry := index.sorted[position]
		if !strings.HasPrefix(entry.Key, matchPrefix) {
			break
		}
		selected = append(selected, entry)
	}
	return selected, nil
}

func (server *Server) walkObjects(ctx context.Context, matchPrefix, startAfter string, limit int) ([]listContent, error) {
	if limit < 1 || limit > 1001 {
		return nil, fmt.Errorf("invalid listing limit")
	}
	selected := make([]listContent, 0, limit*len(listingNamespaceNames))
	for _, namespace := range listingNamespaceNames {
		if !listingNamespaceMatches(namespace, matchPrefix) {
			continue
		}
		entries, err := server.listing[namespace].selectObjects(ctx, matchPrefix, startAfter, limit)
		if err != nil {
			return nil, fmt.Errorf("list %s namespace: %w", namespace, err)
		}
		selected = append(selected, entries...)
	}
	sort.Slice(selected, func(left, right int) bool { return selected[left].Key < selected[right].Key })
	if len(selected) > limit {
		selected = selected[:limit]
	}
	return selected, nil
}
