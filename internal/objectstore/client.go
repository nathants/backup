package objectstore

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"backup/internal/format"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sys/unix"
)

const (
	maximumManifestBytes = int64(format.MaximumMetadataManifestBytes)
	maximumListedKeys    = 1_000_000
)

type Role string

const (
	RoleWriter Role = "writer"
	RoleReader Role = "reader"
)

type Options struct {
	Mirror              format.Mirror
	Role                Role
	Profile             string
	CAFile              string
	CredentialsProvider aws.CredentialsProvider
	HTTPClient          s3.HTTPClient
}

type Client struct {
	mirror format.Mirror
	bucket string
	prefix string
	role   Role
	client *s3.Client
}

type Object struct {
	Size    uint64
	BLAKE2b string
	SHA256  string
	MD5     string
}

type CreateDisposition int

const (
	CreateFailed CreateDisposition = iota
	CreateAcknowledged
	CreateConflict
	CreateAmbiguous
)

type CreateResult struct {
	Disposition CreateDisposition
	Err         error
}

func rejectAWSEndpointEnvironment() error {
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found && value != "" && (name == "AWS_ENDPOINT_URL" || strings.HasPrefix(name, "AWS_ENDPOINT_URL_")) {
			return fmt.Errorf("AWS SDK endpoint overrides are not allowed")
		}
	}
	return nil
}

func rejectAWSSharedConfigEndpoints(sources []interface{}) error {
	for _, source := range sources {
		var shared *awsconfig.SharedConfig
		switch value := source.(type) {
		case awsconfig.SharedConfig:
			shared = &value
		case *awsconfig.SharedConfig:
			shared = value
		}
		if shared != nil && (shared.BaseEndpoint != "" || shared.ServicesSectionName != "" || len(shared.Services.ServiceValues) != 0) {
			return fmt.Errorf("AWS SDK endpoint overrides are not allowed")
		}
	}
	return nil
}

func New(ctx context.Context, options Options) (*Client, error) {
	if options.Role != RoleWriter && options.Role != RoleReader {
		return nil, fmt.Errorf("invalid mirror role %q", options.Role)
	}
	mirrorBytes, err := format.MarshalMirrors([]format.Mirror{options.Mirror})
	if err != nil || len(mirrorBytes) == 0 {
		return nil, fmt.Errorf("invalid pinned mirror: %w", err)
	}
	bucket, prefix, err := parseS3URL(options.Mirror.S3URL)
	if err != nil {
		return nil, err
	}
	if err := rejectAWSEndpointEnvironment(); err != nil {
		return nil, err
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(options.Mirror.Region),
		awsconfig.WithUseFIPSEndpoint(aws.FIPSEndpointStateDisabled),
		awsconfig.WithUseDualStackEndpoint(aws.DualStackEndpointStateDisabled),
	}
	if options.Profile != "" && options.Profile != "-" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(options.Profile))
	}
	if options.CredentialsProvider != nil {
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(options.CredentialsProvider))
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient, err = trustedHTTPClient(options.CAFile)
		if err != nil {
			return nil, err
		}
	}
	loadOptions = append(loadOptions, awsconfig.WithHTTPClient(httpClient))
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	if err := rejectAWSSharedConfigEndpoints(awsConfig.ConfigSources); err != nil {
		return nil, err
	}
	awsConfig.BaseEndpoint = nil
	awsConfig.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	awsConfig.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	client := s3.NewFromConfig(awsConfig, func(s3Options *s3.Options) {
		if options.Mirror.Endpoint == "-" {
			s3Options.BaseEndpoint = nil
		} else {
			s3Options.BaseEndpoint = aws.String(options.Mirror.Endpoint)
		}
		s3Options.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		s3Options.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		s3Options.UseDualstack = false
		s3Options.UsePathStyle = options.Mirror.Kind != format.MirrorAWSS3
		s3Options.APIOptions = append(s3Options.APIOptions, forceSignedPayload)
	})
	return &Client{mirror: options.Mirror, bucket: bucket, prefix: prefix, role: options.Role, client: client}, nil
}

func forceSignedPayload(stack *middleware.Stack) error {
	_, _ = stack.Finalize.Remove((&v4.UnsignedPayload{}).ID())
	if _, ok := stack.Finalize.Get((&v4.ComputePayloadSHA256{}).ID()); !ok {
		if err := v4.AddComputePayloadSHA256Middleware(stack); err != nil {
			return err
		}
	}
	return nil
}

func (client *Client) PutFile(ctx context.Context, logicalKey, filename string, expected Object) CreateResult {
	file, err := os.Open(filename)
	if err != nil {
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
	defer file.Close()
	return client.PutOpenFile(ctx, logicalKey, file, expected)
}

func (client *Client) PutOpenFile(ctx context.Context, logicalKey string, file *os.File, expected Object) CreateResult {
	if client.role != RoleWriter {
		return CreateResult{Disposition: CreateFailed, Err: fmt.Errorf("writer client required")}
	}
	if file == nil {
		return CreateResult{Disposition: CreateFailed, Err: fmt.Errorf("staged file is required")}
	}
	if err := expected.validate(); err != nil {
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != expected.Size {
		return CreateResult{Disposition: CreateFailed, Err: fmt.Errorf("staged object size/type disagrees with metadata")}
	}
	shaBase64, err := digestBase64(expected.SHA256, sha256.Size)
	if err != nil {
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
	md5Base64, err := digestBase64(expected.MD5, md5.Size)
	if err != nil {
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
	key, err := client.key(logicalKey)
	if err != nil {
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
	input := &s3.PutObjectInput{
		Bucket: &client.bucket, Key: &key, Body: file, ContentLength: aws.Int64(info.Size()),
		IfNoneMatch: aws.String("*"), ChecksumSHA256: &shaBase64,
	}
	if client.mirror.Kind != format.MirrorCloudflareR2 {
		input.ContentMD5 = &md5Base64
	}
	if client.mirror.Kind == format.MirrorAWSS3 {
		input.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	output, err := client.client.PutObject(ctx, input)
	if err == nil {
		if client.mirror.Kind == format.MirrorAWSS3 && output.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return CreateResult{Disposition: CreateFailed, Err: fmt.Errorf("AWS S3 create response did not confirm SSE-S3 AES256")}
		}
		return CreateResult{Disposition: CreateAcknowledged}
	}
	status := responseStatus(err)
	switch {
	case status == http.StatusConflict || status == http.StatusPreconditionFailed:
		return CreateResult{Disposition: CreateConflict, Err: err}
	case status == 0 || status >= 500:
		return CreateResult{Disposition: CreateAmbiguous, Err: err}
	default:
		return CreateResult{Disposition: CreateFailed, Err: err}
	}
}

func (client *Client) Audit(ctx context.Context, logicalKey string, expected Object) error {
	if client.role != RoleReader {
		return fmt.Errorf("reader client required")
	}
	if err := expected.validate(); err != nil {
		return err
	}
	key, err := client.key(logicalKey)
	if err != nil {
		return err
	}
	output, err := client.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &client.bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return err
	}
	if client.mirror.Kind == format.MirrorAWSS3 && output.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		return fmt.Errorf("mirror %s object %s does not report SSE-S3 AES256", client.mirror.Name, logicalKey)
	}
	if output.ContentLength == nil || *output.ContentLength < 0 || uint64(*output.ContentLength) != expected.Size {
		return fmt.Errorf("mirror %s object %s has wrong size", client.mirror.Name, logicalKey)
	}
	expectedSHA, err := digestBase64(expected.SHA256, sha256.Size)
	if err != nil {
		return err
	}
	if output.ChecksumSHA256 == nil || *output.ChecksumSHA256 != expectedSHA {
		return fmt.Errorf("mirror %s object %s lacks the expected full-object SHA-256", client.mirror.Name, logicalKey)
	}
	if output.ChecksumType != "" && output.ChecksumType != types.ChecksumTypeFullObject {
		return fmt.Errorf("mirror %s object %s returned checksum type %q", client.mirror.Name, logicalKey, output.ChecksumType)
	}
	return nil
}

func (client *Client) GetVerified(ctx context.Context, logicalKey string, expected Object, output io.Writer) error {
	if client.role != RoleReader {
		return fmt.Errorf("reader client required")
	}
	if output == nil {
		return fmt.Errorf("output writer is required")
	}
	if err := expected.validate(); err != nil {
		return err
	}
	key, err := client.key(logicalKey)
	if err != nil {
		return err
	}
	response, err := client.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &client.bucket, Key: &key})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	blakeHash, _ := blake2b.New512(nil)
	shaHash := sha256.New()
	md5Hash := md5.New()
	limited := &io.LimitedReader{R: response.Body, N: int64(expected.Size) + 1}
	count, err := io.Copy(io.MultiWriter(output, blakeHash, shaHash, md5Hash), limited)
	if err != nil {
		return err
	}
	if uint64(count) != expected.Size || limited.N != 1 {
		return fmt.Errorf("downloaded object size mismatch")
	}
	if hex.EncodeToString(blakeHash.Sum(nil)) != expected.BLAKE2b || hex.EncodeToString(shaHash.Sum(nil)) != expected.SHA256 || hex.EncodeToString(md5Hash.Sum(nil)) != expected.MD5 {
		return fmt.Errorf("downloaded object checksum mismatch")
	}
	return nil
}

func (client *Client) GetManifest(ctx context.Context, logicalKey, expectedBLAKE2b string) ([]byte, error) {
	if client.role != RoleReader {
		return nil, fmt.Errorf("reader client required")
	}
	key, err := client.key(logicalKey)
	if err != nil {
		return nil, err
	}
	response, err := client.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &client.bucket, Key: &key})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength != nil && (*response.ContentLength < 0 || *response.ContentLength > maximumManifestBytes) {
		return nil, fmt.Errorf("metadata manifest exceeds %d bytes", maximumManifestBytes)
	}
	limited := io.LimitReader(response.Body, maximumManifestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximumManifestBytes {
		return nil, fmt.Errorf("metadata manifest exceeds %d bytes", maximumManifestBytes)
	}
	digest := blake2b.Sum512(data)
	if hex.EncodeToString(digest[:]) != expectedBLAKE2b {
		return nil, fmt.Errorf("metadata manifest BLAKE2b mismatch")
	}
	return data, nil
}

func (client *Client) List(ctx context.Context, logicalPrefix string) ([]string, error) {
	return client.ListLimited(ctx, logicalPrefix, maximumListedKeys)
}

func (client *Client) ListLimited(ctx context.Context, logicalPrefix string, maximum int) ([]string, error) {
	if client.role != RoleReader {
		return nil, fmt.Errorf("reader client required")
	}
	if maximum <= 0 || maximum > maximumListedKeys {
		return nil, fmt.Errorf("invalid mirror listing limit %d", maximum)
	}
	prefix, err := client.listPrefix(logicalPrefix)
	if err != nil {
		return nil, err
	}
	var continuation *string
	var result []string
	seenContinuations := make(map[string]struct{})
	for {
		before := len(result)
		pageSize := maximum - len(result) + 1
		if pageSize > 1000 {
			pageSize = 1000
		}
		output, err := client.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &client.bucket, Prefix: &prefix, ContinuationToken: continuation, MaxKeys: aws.Int32(int32(pageSize))})
		if err != nil {
			return nil, err
		}
		for _, object := range output.Contents {
			if object.Key == nil || !strings.HasPrefix(*object.Key, prefix) {
				return nil, fmt.Errorf("mirror returned an invalid listed key")
			}
			logical := strings.TrimPrefix(*object.Key, client.prefixWithSlash())
			result = append(result, logical)
			if len(result) > maximum {
				return nil, fmt.Errorf("mirror listing exceeds %d keys", maximum)
			}
		}
		if !aws.ToBool(output.IsTruncated) {
			break
		}
		if output.NextContinuationToken == nil || *output.NextContinuationToken == "" {
			return nil, fmt.Errorf("truncated mirror listing lacks a continuation token")
		}
		if len(result) == before {
			return nil, fmt.Errorf("truncated mirror listing did not advance")
		}
		next := *output.NextContinuationToken
		if _, repeated := seenContinuations[next]; repeated {
			return nil, fmt.Errorf("truncated mirror listing repeated a continuation token")
		}
		seenContinuations[next] = struct{}{}
		continuation = &next
	}
	return result, nil
}

func (object Object) validate() error {
	if object.Size > uint64(^uint64(0)>>1)-1 {
		return fmt.Errorf("object is too large")
	}
	for label, value := range map[string]string{"BLAKE2b": object.BLAKE2b, "SHA-256": object.SHA256, "MD5": object.MD5} {
		expectedLength := 128
		if label == "SHA-256" {
			expectedLength = 64
		} else if label == "MD5" {
			expectedLength = 32
		}
		if len(value) != expectedLength || strings.ToLower(value) != value {
			return fmt.Errorf("invalid %s digest", label)
		}
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("invalid %s digest", label)
		}
	}
	return nil
}

func (client *Client) key(logical string) (string, error) {
	if logical == "" || strings.HasPrefix(logical, "/") || strings.ContainsAny(logical, "\x00\r\n") || path.Clean(logical) != logical || !safeLogicalComponents(logical) {
		return "", fmt.Errorf("invalid logical object key %q", logical)
	}
	if client.prefix == "" {
		return logical, nil
	}
	return client.prefix + "/" + logical, nil
}

func (client *Client) listPrefix(logical string) (string, error) {
	if logical == "" || strings.HasPrefix(logical, "/") || strings.ContainsAny(logical, "\x00\r\n") {
		return "", fmt.Errorf("invalid logical object prefix %q", logical)
	}
	trailingSlash := strings.HasSuffix(logical, "/")
	cleaned := strings.TrimSuffix(logical, "/")
	if cleaned == "" || path.Clean(cleaned) != cleaned || !safeLogicalComponents(cleaned) {
		return "", fmt.Errorf("invalid logical object prefix %q", logical)
	}
	if trailingSlash {
		cleaned += "/"
	}
	if client.prefix == "" {
		return cleaned, nil
	}
	return client.prefix + "/" + cleaned, nil
}

func safeLogicalComponents(value string) bool {
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func (client *Client) prefixWithSlash() string {
	if client.prefix == "" {
		return ""
	}
	return client.prefix + "/"
}

func parseS3URL(value string) (string, string, error) {
	parts := strings.SplitN(strings.TrimPrefix(value, "s3://"), "/", 2)
	if len(parts) == 0 || parts[0] == "" || !strings.HasPrefix(value, "s3://") {
		return "", "", fmt.Errorf("invalid S3 URL %q", value)
	}
	prefix := ""
	if len(parts) == 2 {
		prefix = parts[1]
	}
	return parts[0], prefix, nil
}

func digestBase64(value string, size int) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size {
		return "", fmt.Errorf("invalid checksum digest")
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

func responseStatus(err error) int {
	var responseError *smithyhttp.ResponseError
	if errors.As(err, &responseError) {
		return responseError.HTTPStatusCode()
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "PreconditionFailed":
			return http.StatusPreconditionFailed
		case "Conflict", "KeyAlreadyExists":
			return http.StatusConflict
		}
	}
	return 0
}

func readTrustedCAFile(filename string) ([]byte, error) {
	const maximumCAFileBytes = int64(4 << 20)
	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open mirror CA file as a regular no-follow file: %w", err)
	}
	file := os.NewFile(uintptr(fd), filename)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > maximumCAFileBytes {
		return nil, fmt.Errorf("mirror CA file must be a nonempty bounded regular file without group/other write permissions")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumCAFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("mirror CA file size changed while reading")
	}
	return data, nil
}

const (
	responseHeaderTimeout = 2 * time.Minute
	transferIdleTimeout   = 5 * time.Minute
)

type inactivityDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *inactivityDeadlineConn) Read(data []byte) (int, error) {
	if err := connection.SetReadDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Read(data)
}

func (connection *inactivityDeadlineConn) Write(data []byte) (int, error) {
	if err := connection.SetWriteDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Write(data)
}

func trustedHTTPClient(caFile string) (*http.Client, error) {
	return trustedHTTPClientWithTimeouts(caFile, responseHeaderTimeout, transferIdleTimeout)
}

func trustedHTTPClientWithTimeouts(caFile string, headerTimeout, idleTimeout time.Duration) (*http.Client, error) {
	if headerTimeout <= 0 || idleTimeout <= 0 {
		return nil, fmt.Errorf("mirror HTTP timeouts must be positive")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system trust roots: %w", err)
	}
	if caFile != "" && caFile != "-" {
		data, err := readTrustedCAFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read mirror CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("mirror CA file contains no valid certificates")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	transport.Proxy = http.ProxyFromEnvironment
	transport.ResponseHeaderTimeout = headerTimeout
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &inactivityDeadlineConn{Conn: connection, timeout: idleTimeout}, nil
	}
	return &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("mirror endpoint redirects are forbidden")
		},
	}, nil
}

func HashReader(reader io.Reader) (Object, error) {
	if reader == nil {
		return Object{}, fmt.Errorf("object reader is required")
	}
	blakeHash, _ := blake2b.New512(nil)
	shaHash := sha256.New()
	md5Hash := md5.New()
	count, err := io.Copy(io.MultiWriter(blakeHash, shaHash, md5Hash), reader)
	if err != nil {
		return Object{}, err
	}
	return Object{Size: uint64(count), BLAKE2b: hex.EncodeToString(blakeHash.Sum(nil)), SHA256: hex.EncodeToString(shaHash.Sum(nil)), MD5: hex.EncodeToString(md5Hash.Sum(nil))}, nil
}

func HashBytes(data []byte) Object {
	blakeDigest := blake2b.Sum512(data)
	shaDigest := sha256.Sum256(data)
	md5Digest := md5.Sum(data)
	return Object{Size: uint64(len(data)), BLAKE2b: hex.EncodeToString(blakeDigest[:]), SHA256: hex.EncodeToString(shaDigest[:]), MD5: hex.EncodeToString(md5Digest[:])}
}

func VerifyBytes(data []byte, expected Object) error {
	actual := HashBytes(data)
	if actual != expected {
		return fmt.Errorf("object bytes disagree with expected identity")
	}
	return nil
}
