package integration

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backup/internal/format"
	"backup/internal/objectstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type cloudContractConfig struct {
	name       string
	kind       string
	bucket     string
	prefix     string
	endpoint   string
	region     string
	writer     aws.Credentials
	reader     aws.Credentials
	requireSSE bool
}

func TestAWSCloudContract(t *testing.T) {
	if os.Getenv("BACKUP_AWS_CONTRACT") != "1" {
		t.Skip("set BACKUP_AWS_CONTRACT=1 with dedicated contract credentials")
	}
	config := contractConfigFromEnvironment(t, "AWS", format.MirrorAWSS3)
	config.requireSSE = true
	runCloudContract(t, config)
}

func TestCloudflareR2Contract(t *testing.T) {
	if os.Getenv("BACKUP_R2_CONTRACT") != "1" {
		t.Skip("set BACKUP_R2_CONTRACT=1 after enabling an indefinite bucket-lock rule")
	}
	config := contractConfigFromEnvironment(t, "R2", format.MirrorCloudflareR2)
	runCloudContract(t, config)
}

func contractConfigFromEnvironment(t *testing.T, label, kind string) cloudContractConfig {
	t.Helper()
	get := func(name string) string {
		value := os.Getenv("BACKUP_" + label + "_CONTRACT_" + name)
		if value == "" {
			t.Fatalf("BACKUP_%s_CONTRACT_%s is required", label, name)
		}
		return value
	}
	config := cloudContractConfig{
		name: label, kind: kind, bucket: get("BUCKET"), prefix: strings.Trim(os.Getenv("BACKUP_"+label+"_CONTRACT_PREFIX"), "/"),
		region: get("REGION"),
		writer: aws.Credentials{AccessKeyID: get("WRITER_ACCESS_KEY"), SecretAccessKey: get("WRITER_SECRET_KEY"), SessionToken: os.Getenv("BACKUP_" + label + "_CONTRACT_WRITER_SESSION_TOKEN")},
		reader: aws.Credentials{AccessKeyID: get("READER_ACCESS_KEY"), SecretAccessKey: get("READER_SECRET_KEY"), SessionToken: os.Getenv("BACKUP_" + label + "_CONTRACT_READER_SESSION_TOKEN")},
	}
	config.endpoint = os.Getenv("BACKUP_" + label + "_CONTRACT_ENDPOINT")
	if kind == format.MirrorCloudflareR2 && config.endpoint == "" {
		t.Fatal("R2 contract requires an exact endpoint")
	}
	if config.writer.AccessKeyID == config.reader.AccessKeyID {
		t.Fatal("cloud contract requires distinct writer and reader credentials")
	}
	return config
}

func createAndAuditCloudProbe(ctx context.Context, kind string, writer, reader *objectstore.Client, logicalKey, staged string, expected objectstore.Object) error {
	if kind != format.MirrorAWSS3 {
		created := writer.PutFile(ctx, logicalKey, staged, expected)
		if created.Disposition != objectstore.CreateAcknowledged {
			return fmt.Errorf("production client could not create immutable probe: %w", created.Err)
		}
		if err := reader.Audit(ctx, logicalKey, expected); err != nil {
			return fmt.Errorf("checksum HEAD did not validate the probe: %w", err)
		}
		return nil
	}

	readinessCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	writeConfirmed := false
	var lastErr error
	for {
		auditCandidate := writeConfirmed
		if !writeConfirmed {
			created := writer.PutFile(readinessCtx, logicalKey, staged, expected)
			switch created.Disposition {
			case objectstore.CreateAcknowledged, objectstore.CreateConflict:
				writeConfirmed = true
				auditCandidate = true
			case objectstore.CreateAmbiguous:
				auditCandidate = true
				lastErr = created.Err
			default:
				lastErr = created.Err
			}
		}
		if auditCandidate {
			if err := reader.Audit(readinessCtx, logicalKey, expected); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-readinessCtx.Done():
			timer.Stop()
			if lastErr == nil {
				lastErr = readinessCtx.Err()
			}
			return fmt.Errorf("AWS writer/reader policies did not become ready: %w", lastErr)
		case <-timer.C:
		}
	}
}

func runCloudContract(t *testing.T, config cloudContractConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	namespace := "contract-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + randomContractHex(t, 8)
	contractPrefix := config.prefix + "/" + namespace
	contractPrefix = strings.TrimPrefix(contractPrefix, "/")
	endpoint := config.endpoint
	if endpoint == "" {
		endpoint = "-"
	}
	mirror := format.Mirror{Name: "contract", Kind: config.kind, S3URL: "s3://" + config.bucket + "/" + contractPrefix, Endpoint: endpoint, Region: config.region}
	writer, err := objectstore.New(ctx, objectstore.Options{Mirror: mirror, Role: objectstore.RoleWriter, CredentialsProvider: credentials.NewStaticCredentialsProvider(config.writer.AccessKeyID, config.writer.SecretAccessKey, config.writer.SessionToken)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &methodRecorder{client: contractHTTPClient()}
	reader, err := objectstore.New(ctx, objectstore.Options{Mirror: mirror, Role: objectstore.RoleReader, CredentialsProvider: credentials.NewStaticCredentialsProvider(config.reader.AccessKeyID, config.reader.SecretAccessKey, config.reader.SessionToken), HTTPClient: recorder})
	if err != nil {
		t.Fatal(err)
	}
	writerS3 := directCloudClient(config, config.writer)
	readerS3 := directCloudClient(config, config.reader)

	payload := bytes.Repeat([]byte("immutable-backup-contract\n"), 128)
	expected := objectstore.HashBytes(payload)
	logicalKey := "objects/" + expected.BLAKE2b + "/" + randomContractHex(t, 16)
	wireKey := contractPrefix + "/" + logicalKey
	staged := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(staged, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createAndAuditCloudProbe(ctx, config.kind, writer, reader, logicalKey, staged, expected); err != nil {
		t.Fatal(err)
	}
	t.Logf("immutable probe: s3://%s/%s", config.bucket, wireKey)
	if config.kind == format.MirrorCloudflareR2 {
		runR2LockProtectionContract(t, ctx, config, reader, logicalKey, expected, contractPrefix)
	}
	if recorder.count(http.MethodGet) != 0 || recorder.count(http.MethodHead) == 0 {
		t.Fatalf("cloud audit methods: HEAD=%d GET=%d", recorder.count(http.MethodHead), recorder.count(http.MethodGet))
	}
	conflict := writer.PutFile(ctx, logicalKey, staged, expected)
	if conflict.Disposition != objectstore.CreateConflict {
		t.Fatalf("conditional retry disposition=%d error=%v", conflict.Disposition, conflict.Err)
	}

	_, writerHeadErr := writerS3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &config.bucket, Key: &wireKey})
	requireCloudHTTPStatus(t, "writer HEAD", writerHeadErr, http.StatusForbidden)
	_, writerListErr := writerS3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &config.bucket, Prefix: &contractPrefix, MaxKeys: aws.Int32(1)})
	requireCloudHTTPStatus(t, "writer LIST", writerListErr, http.StatusForbidden)
	readerWritePayload := []byte("reader must not write")
	readerWriteObject := objectstore.HashBytes(readerWritePayload)
	readerWriteKey := contractPrefix + "/objects/" + readerWriteObject.BLAKE2b + "/" + randomContractHex(t, 16)
	_, readerWriteErr := readerS3.PutObject(ctx, contractPutInput(config, readerWriteKey, readerWritePayload, true))
	requireCloudHTTPStatus(t, "reader create", readerWriteErr, http.StatusForbidden)
	assertCloudKeyAbsent(t, ctx, readerS3, config.bucket, readerWriteKey, "reader create")

	wrongChecksumPayload := []byte("wrong checksum must be rejected")
	wrongChecksumObject := objectstore.HashBytes(wrongChecksumPayload)
	wrongChecksumKey := contractPrefix + "/objects/" + wrongChecksumObject.BLAKE2b + "/" + randomContractHex(t, 16)
	wrong := contractPutInput(config, wrongChecksumKey, wrongChecksumPayload, true)
	wrong.ChecksumSHA256 = aws.String(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	_, wrongChecksumErr := writerS3.PutObject(ctx, wrong)
	requireCloudClientRejection(t, "wrong-checksum create", wrongChecksumErr)
	assertCloudKeyAbsent(t, ctx, readerS3, config.bucket, wrongChecksumKey, "wrong-checksum create")

	if config.kind == format.MirrorAWSS3 {
		runAWSCreateProtectionContract(t, ctx, config, writerS3, readerS3)
		unconditionalPayload := []byte("AWS policy must require If-None-Match")
		unconditionalObject := objectstore.HashBytes(unconditionalPayload)
		unconditionalKey := contractPrefix + "/objects/" + unconditionalObject.BLAKE2b + "/" + randomContractHex(t, 16)
		_, unconditionalErr := writerS3.PutObject(ctx, contractPutInput(config, unconditionalKey, unconditionalPayload, false))
		requireCloudHTTPStatus(t, "unconditional create", unconditionalErr, http.StatusForbidden)
		assertCloudKeyAbsent(t, ctx, readerS3, config.bucket, unconditionalKey, "unconditional create")
	}

	overwritePayload := []byte("malicious overwrite")
	_, overwriteErr := writerS3.PutObject(ctx, contractPutInput(config, wireKey, overwritePayload, false))
	requireCloudClientRejection(t, "unconditional overwrite", overwriteErr)
	assertCloudProbe(t, ctx, reader, logicalKey, expected, "unconditional overwrite")
	_, deleteErr := writerS3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &config.bucket, Key: &wireKey})
	requireCloudClientRejection(t, "delete", deleteErr)
	assertCloudProbe(t, ctx, reader, logicalKey, expected, "delete")
	probeHead, err := readerS3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &config.bucket, Key: &wireKey, ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		t.Fatalf("reader could not inspect retained probe version: %v", err)
	}
	probeVersion := aws.ToString(probeHead.VersionId)
	if config.kind == format.MirrorAWSS3 && probeVersion == "" {
		t.Fatal("versioned AWS contract probe did not report a VersionId")
	}
	if probeVersion != "" {
		_, versionDeleteErr := writerS3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &config.bucket, Key: &wireKey, VersionId: &probeVersion})
		requireCloudClientRejection(t, "version-specific delete", versionDeleteErr)
		assertCloudProbe(t, ctx, reader, logicalKey, expected, "version-specific delete")
	}
	batchOutput, batchErr := writerS3.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &config.bucket, Delete: &types.Delete{Objects: []types.ObjectIdentifier{{Key: &wireKey, VersionId: probeHead.VersionId}}}})
	if batchErr != nil {
		requireCloudClientRejection(t, "batch delete", batchErr)
	} else if batchOutput == nil || len(batchOutput.Errors) == 0 || len(batchOutput.Deleted) != 0 || aws.ToString(batchOutput.Errors[0].Key) != wireKey || aws.ToString(batchOutput.Errors[0].Code) == "" {
		t.Fatalf("batch delete did not return an explicit per-object rejection: %#v", batchOutput)
	}
	assertCloudProbe(t, ctx, reader, logicalKey, expected, "batch delete")
	_, copyErr := writerS3.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &config.bucket, Key: &wireKey, CopySource: aws.String(url.PathEscape(config.bucket + "/" + wireKey))})
	requireCloudClientRejection(t, "copy overwrite", copyErr)
	assertCloudProbe(t, ctx, reader, logicalKey, expected, "copy overwrite")

	multipart, multipartErr := writerS3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &config.bucket, Key: &wireKey})
	if multipartErr != nil {
		requireCloudClientRejection(t, "multipart overwrite initiation", multipartErr)
	} else {
		if multipart == nil || multipart.UploadId == nil {
			t.Fatal("multipart overwrite initiation returned no upload ID")
		}
		partPayload := []byte("malicious multipart overwrite")
		part, partErr := writerS3.UploadPart(ctx, &s3.UploadPartInput{Bucket: &config.bucket, Key: &wireKey, UploadId: multipart.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader(partPayload)})
		if partErr != nil {
			requireCloudClientRejection(t, "multipart overwrite part", partErr)
		} else {
			if part == nil || part.ETag == nil {
				t.Fatal("multipart overwrite part returned no ETag")
			}
			_, completeErr := writerS3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &config.bucket, Key: &wireKey, UploadId: multipart.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1)}}}})
			requireCloudClientRejection(t, "multipart overwrite completion", completeErr)
		}
	}
	assertCloudProbe(t, ctx, reader, logicalKey, expected, "multipart overwrite")

	if config.kind == format.MirrorAWSS3 {
		runAWSControlPlaneProtectionContract(t, ctx, config, writerS3, reader, logicalKey, expected)
	}
}

func runAWSCreateProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, writer, reader *s3.Client) {
	t.Helper()
	payload := []byte("default SSE-S3 upload")
	object := objectstore.HashBytes(payload)
	key := strings.Trim(config.prefix, "/") + "/contract-default-encryption-" + randomContractHex(t, 8) + "/objects/" + object.BLAKE2b + "/" + randomContractHex(t, 16)
	key = strings.TrimPrefix(key, "/")
	input := contractPutInput(config, key, payload, true)
	input.ServerSideEncryption = ""
	if _, err := writer.PutObject(ctx, input); err != nil {
		t.Fatalf("AWS default-encryption create failed: %v", err)
	}
	head, err := reader.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &config.bucket, Key: &key})
	if err != nil {
		t.Fatalf("inspect AWS default-encryption object: %v", err)
	}
	if head.ServerSideEncryption != types.ServerSideEncryptionAes256 {
		t.Fatalf("AWS default encryption=%q, want AES256", head.ServerSideEncryption)
	}
	t.Logf("default-encrypted probe: s3://%s/%s", config.bucket, key)

	t.Run("AWS rejects SSE-C", func(t *testing.T) {
		payload := []byte("rejected SSE-C upload")
		object := objectstore.HashBytes(payload)
		key := strings.Trim(config.prefix, "/") + "/contract-encryption-" + randomContractHex(t, 8) + "/objects/" + object.BLAKE2b + "/" + randomContractHex(t, 16)
		key = strings.TrimPrefix(key, "/")
		input := contractPutInput(config, key, payload, true)
		input.ServerSideEncryption = ""
		customerKey := bytes.Repeat([]byte{0x42}, 32)
		digest := md5.Sum(customerKey)
		input.SSECustomerAlgorithm = aws.String("AES256")
		input.SSECustomerKey = aws.String(base64.StdEncoding.EncodeToString(customerKey))
		input.SSECustomerKeyMD5 = aws.String(base64.StdEncoding.EncodeToString(digest[:]))
		_, err := writer.PutObject(ctx, input)
		requireCloudHTTPStatus(t, "SSE-C", err, http.StatusForbidden)
		assertCloudKeyAbsent(t, ctx, reader, config.bucket, key, "SSE-C")
	})
}

func runAWSControlPlaneProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, writer *s3.Client, reader *objectstore.Client, probeKey string, expected objectstore.Object) {
	t.Helper()
	assertDenied := func(operation string, err error) {
		t.Helper()
		requireCloudHTTPStatus(t, operation, err, http.StatusForbidden)
		assertCloudProbe(t, ctx, reader, probeKey, expected, operation)
	}
	_, err := writer.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &config.bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusSuspended}})
	assertDenied("suspend bucket versioning", err)
	_, err = writer.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{Bucket: &config.bucket, ObjectLockConfiguration: &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled}})
	assertDenied("alter object-lock configuration", err)
	publicAccess := &types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(false), IgnorePublicAcls: aws.Bool(false), BlockPublicPolicy: aws.Bool(false), RestrictPublicBuckets: aws.Bool(false)}
	_, err = writer.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: &config.bucket, PublicAccessBlockConfiguration: publicAccess})
	assertDenied("weaken public-access blocking", err)
	_, err = writer.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &config.bucket})
	assertDenied("delete public-access blocking", err)
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`, config.bucket, config.bucket)
	_, err = writer.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &config.bucket, Policy: &policy})
	assertDenied("replace bucket policy", err)
	_, err = writer.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &config.bucket})
	assertDenied("delete bucket policy", err)
	_, err = writer.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{Bucket: &config.bucket})
	assertDenied("delete bucket encryption", err)
	_, err = writer.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{Bucket: &config.bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{ID: aws.String("malicious-expiry"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{}, Expiration: &types.LifecycleExpiration{Days: aws.Int32(1)}}}}})
	assertDenied("install destructive lifecycle policy", err)
}

type r2LockEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		Rules []json.RawMessage `json:"rules"`
	} `json:"result"`
}

type r2LockRule struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"`
	Prefix    string `json:"prefix"`
	Condition struct {
		Type string `json:"type"`
	} `json:"condition"`
}

func runR2LockProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, reader *objectstore.Client, probeKey string, expected objectstore.Object, contractPrefix string) {
	t.Helper()
	accountID := os.Getenv("BACKUP_R2_CONTRACT_ACCOUNT_ID")
	auditToken := os.Getenv("BACKUP_R2_CONTRACT_LOCK_AUDIT_TOKEN")
	if len(accountID) != 32 || strings.ToLower(accountID) != accountID {
		t.Fatal("BACKUP_R2_CONTRACT_ACCOUNT_ID must be the 32-character lowercase account ID")
	}
	if _, err := hex.DecodeString(accountID); err != nil {
		t.Fatal("BACKUP_R2_CONTRACT_ACCOUNT_ID must be lowercase hexadecimal")
	}
	if auditToken == "" {
		t.Fatal("BACKUP_R2_CONTRACT_LOCK_AUDIT_TOKEN with Workers R2 Storage Read is required")
	}
	if auditToken == config.writer.AccessKeyID || auditToken == config.writer.SecretAccessKey || auditToken == config.reader.AccessKeyID || auditToken == config.reader.SecretAccessKey {
		t.Fatal("R2 lock-audit token must be distinct from all S3 credential values")
	}
	endpoint := "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/r2/buckets/" + url.PathEscape(config.bucket) + "/lock"
	jurisdiction := os.Getenv("BACKUP_R2_CONTRACT_JURISDICTION")
	before := getR2LockRules(t, ctx, endpoint, auditToken, jurisdiction)
	covered := false
	wirePrefix := strings.TrimPrefix(contractPrefix, "/") + "/"
	for _, raw := range before.Result.Rules {
		var rule r2LockRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatalf("decode R2 lock rule: %v", err)
		}
		if rule.ID == "" || rule.Condition.Type == "" {
			t.Fatal("R2 lock audit returned a malformed rule")
		}
		if rule.Enabled && rule.Condition.Type == "Indefinite" && (rule.Prefix == "" || strings.HasPrefix(wirePrefix, rule.Prefix)) {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("no enabled indefinite R2 lock rule covers prefix %q", wirePrefix)
	}
	mutationBody, err := json.Marshal(struct {
		Rules []json.RawMessage `json:"rules"`
	}{Rules: before.Result.Rules})
	if err != nil {
		t.Fatal(err)
	}
	for label, token := range map[string]string{"access-key ID": config.writer.AccessKeyID, "secret access key": config.writer.SecretAccessKey} {
		status, _, err := doR2LockRequest(ctx, http.MethodPut, endpoint, token, jurisdiction, mutationBody)
		if err != nil {
			t.Fatalf("R2 lock mutation attempt with %s: %v", label, err)
		}
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatalf("ordinary R2 %s reached lock control plane: HTTP %d", label, status)
		}
		assertCloudProbe(t, ctx, reader, probeKey, expected, "R2 lock mutation with "+label)
	}
	after := getR2LockRules(t, ctx, endpoint, auditToken, jurisdiction)
	beforeRules, _ := json.Marshal(before.Result.Rules)
	afterRules, _ := json.Marshal(after.Result.Rules)
	if !bytes.Equal(beforeRules, afterRules) {
		t.Fatal("R2 lock rules changed during ordinary-credential mutation tests")
	}
}

func getR2LockRules(t *testing.T, ctx context.Context, endpoint, token, jurisdiction string) r2LockEnvelope {
	t.Helper()
	status, data, err := doR2LockRequest(ctx, http.MethodGet, endpoint, token, jurisdiction, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("R2 lock audit returned HTTP %d", status)
	}
	var result r2LockEnvelope
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode R2 lock audit: %v", err)
	}
	if !result.Success || len(result.Errors) != 0 || result.Result.Rules == nil {
		t.Fatalf("R2 lock audit was not a successful rules response: success=%t errors=%d", result.Success, len(result.Errors))
	}
	return result
}

func doR2LockRequest(ctx context.Context, method, endpoint, token, jurisdiction string, body []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}
	if jurisdiction != "" {
		if jurisdiction != "default" && jurisdiction != "eu" && jurisdiction != "fedramp" {
			return 0, nil, fmt.Errorf("invalid BACKUP_R2_CONTRACT_JURISDICTION")
		}
		request.Header.Set("cf-r2-jurisdiction", jurisdiction)
	}
	response, err := contractHTTPClient().Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	const maximumResponse = 1 << 20
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponse+1))
	if readErr != nil {
		return 0, nil, readErr
	}
	if len(data) > maximumResponse {
		return 0, nil, fmt.Errorf("R2 lock response exceeds %d bytes", maximumResponse)
	}
	return response.StatusCode, data, nil
}

func directCloudClient(config cloudContractConfig, credential aws.Credentials) *s3.Client {
	loaded := aws.Config{
		Region:      config.region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken)),
		HTTPClient:  contractHTTPClient(),
	}
	loaded.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	loaded.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	return s3.NewFromConfig(loaded, func(options *s3.Options) {
		if config.endpoint == "" {
			options.BaseEndpoint = nil
		} else {
			options.BaseEndpoint = &config.endpoint
		}
		options.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		options.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		options.UsePathStyle = config.kind != format.MirrorAWSS3
	})
}

func contractPutInput(config cloudContractConfig, key string, payload []byte, conditional bool) *s3.PutObjectInput {
	object := objectstore.HashBytes(payload)
	input := &s3.PutObjectInput{
		Bucket: &config.bucket, Key: &key, Body: bytes.NewReader(payload), ContentLength: aws.Int64(int64(len(payload))),
		ChecksumSHA256: aws.String(base64Digest(object.SHA256)),
	}
	if config.kind != format.MirrorCloudflareR2 {
		input.ContentMD5 = aws.String(base64Digest(object.MD5))
	}
	if conditional {
		input.IfNoneMatch = aws.String("*")
	}
	if config.requireSSE {
		input.ServerSideEncryption = types.ServerSideEncryptionAes256
	}
	return input
}

func base64Digest(value string) string {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(decoded)
}

func cloudHTTPStatus(err error) (int, bool) {
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response == nil || response.Response == nil || response.Response.Response == nil {
		return 0, false
	}
	return response.HTTPStatusCode(), true
}

func cloudClientRejection(err error) (int, bool) {
	status, ok := cloudHTTPStatus(err)
	if !ok {
		return status, false
	}
	switch status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusConflict, http.StatusPreconditionFailed:
		return status, true
	default:
		return status, false
	}
}

func requireCloudClientRejection(t *testing.T, operation string, err error) {
	t.Helper()
	status, ok := cloudClientRejection(err)
	if !ok {
		t.Fatalf("%s did not return an accepted provider rejection: status=%d error=%v", operation, status, err)
	}
}

func requireCloudHTTPStatus(t *testing.T, operation string, err error, allowed ...int) {
	t.Helper()
	status, ok := cloudHTTPStatus(err)
	if !ok {
		t.Fatalf("%s did not return a provider HTTP rejection: %v", operation, err)
	}
	for _, expected := range allowed {
		if status == expected {
			return
		}
	}
	t.Fatalf("%s returned HTTP %d, expected one of %v: %v", operation, status, allowed, err)
}

func TestCloudContractHTTPRejectionClassification(t *testing.T) {
	if _, ok := cloudHTTPStatus(errors.New("local validation failure")); ok {
		t.Fatal("local error was accepted as a provider rejection")
	}
	for _, test := range []struct {
		status   int
		accepted bool
	}{{http.StatusBadRequest, true}, {http.StatusForbidden, true}, {http.StatusPreconditionFailed, true}, {http.StatusTooManyRequests, false}, {http.StatusInternalServerError, false}} {
		err := &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: test.status}},
			Err:      errors.New("provider response"),
		}
		status, accepted := cloudClientRejection(err)
		if status != test.status || accepted != test.accepted {
			t.Fatalf("status %d rejection=%t, want status %d rejection %t", status, accepted, test.status, test.accepted)
		}
	}
}

func assertCloudKeyAbsent(t *testing.T, ctx context.Context, reader *s3.Client, bucket, key, operation string) {
	t.Helper()
	_, err := reader.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err == nil {
		t.Fatalf("key created by rejected %s", operation)
	}
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusNotFound {
		t.Fatalf("could not prove key absence after %s: %v", operation, err)
	}
}

func assertCloudProbe(t *testing.T, ctx context.Context, reader *objectstore.Client, key string, expected objectstore.Object, operation string) {
	t.Helper()
	if err := reader.Audit(ctx, key, expected); err != nil {
		t.Fatalf("probe changed after %s attempt: %v", operation, err)
	}
}

func randomContractHex(t *testing.T, count int) string {
	t.Helper()
	data := make([]byte, count)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(data)
}

func contractHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("cloud contract redirect forbidden") }}
}

type methodRecorder struct {
	client *http.Client
	mutex  sync.Mutex
	counts map[string]int
}

func (recorder *methodRecorder) Do(request *http.Request) (*http.Response, error) {
	recorder.mutex.Lock()
	if recorder.counts == nil {
		recorder.counts = make(map[string]int)
	}
	recorder.counts[request.Method]++
	recorder.mutex.Unlock()
	return recorder.client.Do(request)
}

func (recorder *methodRecorder) count(method string) int {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return recorder.counts[method]
}
