package integration

import (
	"bytes"
	"context"
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
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

type cloudContractConfig struct {
	name       string
	kind       string
	bucket     string
	prefix     string
	endpoint   string
	region     string
	credential aws.Credentials
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
		region:     get("REGION"),
		credential: aws.Credentials{AccessKeyID: get("ACCESS_KEY"), SecretAccessKey: get("SECRET_KEY"), SessionToken: os.Getenv("BACKUP_" + label + "_CONTRACT_SESSION_TOKEN")},
	}
	config.endpoint = os.Getenv("BACKUP_" + label + "_CONTRACT_ENDPOINT")
	if kind == format.MirrorCloudflareR2 && config.endpoint == "" {
		t.Fatal("R2 contract requires an exact endpoint")
	}
	return config
}

func createAndAuditCloudProbe(ctx context.Context, kind string, client *objectstore.Client, logicalKey, staged string, expected objectstore.Object) error {
	if kind != format.MirrorAWSS3 {
		created := client.PutFile(ctx, logicalKey, staged, expected)
		if created.Disposition != objectstore.CreateAcknowledged {
			return fmt.Errorf("production client could not create immutable probe: %w", created.Err)
		}
		if err := client.Audit(ctx, logicalKey, expected); err != nil {
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
			created := client.PutFile(readinessCtx, logicalKey, staged, expected)
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
			if err := client.Audit(readinessCtx, logicalKey, expected); err == nil {
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
			return fmt.Errorf("AWS client policy did not become ready: %w", lastErr)
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
	recorder := &methodRecorder{client: contractHTTPClient()}
	client, err := objectstore.New(ctx, objectstore.Options{Mirror: mirror, CredentialsProvider: credentials.NewStaticCredentialsProvider(config.credential.AccessKeyID, config.credential.SecretAccessKey, config.credential.SessionToken), HTTPClient: recorder})
	if err != nil {
		t.Fatal(err)
	}
	s3Client := directCloudClient(config, config.credential)

	payload := bytes.Repeat([]byte("immutable-backup-contract\n"), 128)
	expected := objectstore.HashBytes(payload)
	logicalKey := "objects/" + expected.BLAKE2b + "/" + randomContractHex(t, 16)
	wireKey := contractPrefix + "/" + logicalKey
	staged := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(staged, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createAndAuditCloudProbe(ctx, config.kind, client, logicalKey, staged, expected); err != nil {
		t.Fatal(err)
	}
	t.Logf("immutable probe: s3://%s/%s", config.bucket, wireKey)
	if config.kind == format.MirrorCloudflareR2 {
		runR2LockProtectionContract(t, ctx, config, client, logicalKey, expected)
	}
	if recorder.count(http.MethodGet) != 0 || recorder.count(http.MethodHead) == 0 {
		t.Fatalf("cloud audit methods: HEAD=%d GET=%d", recorder.count(http.MethodHead), recorder.count(http.MethodGet))
	}
	conflict := client.PutFile(ctx, logicalKey, staged, expected)
	if conflict.Disposition != objectstore.CreateConflict {
		t.Fatalf("conditional retry disposition=%d error=%v", conflict.Disposition, conflict.Err)
	}

	// Read/list are intentional ordinary-client capabilities on every backend.
	var downloaded bytes.Buffer
	if err := client.GetVerified(ctx, logicalKey, expected, &downloaded); err != nil || !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("ordinary client cannot read its probe: %v", err)
	}
	keys, err := client.List(ctx, "objects/")
	if err != nil || len(keys) != 1 || keys[0] != logicalKey {
		t.Fatalf("ordinary client cannot list its probe: %v keys=%v", err, keys)
	}

	wrongChecksumPayload := []byte("wrong checksum must be rejected")
	wrongChecksumObject := objectstore.HashBytes(wrongChecksumPayload)
	wrongChecksumKey := contractPrefix + "/objects/" + wrongChecksumObject.BLAKE2b + "/" + randomContractHex(t, 16)
	wrong := contractPutInput(config, wrongChecksumKey, wrongChecksumPayload, true)
	wrong.ChecksumSHA256 = aws.String(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	_, wrongChecksumErr := s3Client.PutObject(ctx, wrong)
	requireCloudAPIError(t, "wrong-checksum create", wrongChecksumErr, http.StatusBadRequest, "BadDigest")
	assertCloudKeyAbsent(t, ctx, s3Client, config.bucket, wrongChecksumKey, "wrong-checksum create")
	if _, err := s3Client.PutObject(ctx, contractPutInput(config, wrongChecksumKey, wrongChecksumPayload, true)); err != nil {
		t.Fatalf("correct-checksum positive control failed: %v", err)
	}

	if config.kind == format.MirrorAWSS3 {
		runAWSCreateProtectionContract(t, ctx, config, s3Client)
		unconditionalPayload := []byte("AWS policy must require If-None-Match")
		unconditionalObject := objectstore.HashBytes(unconditionalPayload)
		unconditionalKey := contractPrefix + "/objects/" + unconditionalObject.BLAKE2b + "/" + randomContractHex(t, 16)
		_, unconditionalErr := s3Client.PutObject(ctx, contractPutInput(config, unconditionalKey, unconditionalPayload, false))
		requireCloudHTTPStatus(t, "unconditional create", unconditionalErr, http.StatusForbidden)
		assertCloudKeyAbsent(t, ctx, s3Client, config.bucket, unconditionalKey, "unconditional create")
	}

	overwritePayload := []byte("malicious overwrite")
	_, overwriteErr := s3Client.PutObject(ctx, contractPutInput(config, wireKey, overwritePayload, false))
	requireCloudClientRejection(t, "unconditional overwrite", overwriteErr)
	assertCloudProbe(t, ctx, client, logicalKey, expected, "unconditional overwrite")
	sseOverwrite := contractPutInput(config, wireKey, overwritePayload, false)
	sseOverwrite.ServerSideEncryption = ""
	setContractSSECustomerKey(sseOverwrite)
	_, sseErr := s3Client.PutObject(ctx, sseOverwrite)
	requireCloudClientRejection(t, "SSE-C overwrite", sseErr)
	assertCloudProbe(t, ctx, client, logicalKey, expected, "SSE-C overwrite")
	_, deleteErr := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &config.bucket, Key: &wireKey})
	requireCloudClientRejection(t, "delete", deleteErr)
	assertCloudProbe(t, ctx, client, logicalKey, expected, "delete")
	probeHead, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &config.bucket, Key: &wireKey, ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		t.Fatalf("client could not inspect retained probe version: %v", err)
	}
	probeVersion := aws.ToString(probeHead.VersionId)
	if config.kind == format.MirrorAWSS3 && probeVersion == "" {
		t.Fatal("versioned AWS contract probe did not report a VersionId")
	}
	if probeVersion != "" {
		_, versionDeleteErr := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &config.bucket, Key: &wireKey, VersionId: &probeVersion})
		requireCloudClientRejection(t, "version-specific delete", versionDeleteErr)
		assertCloudProbe(t, ctx, client, logicalKey, expected, "version-specific delete")
	}
	versions := []*string{nil}
	if probeVersion != "" {
		versions = append(versions, &probeVersion)
	}
	for _, version := range versions {
		operation := "batch delete"
		if version != nil {
			operation = "version-specific batch delete"
		}
		batchOutput, batchErr := s3Client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &config.bucket, Delete: &types.Delete{Objects: []types.ObjectIdentifier{{Key: &wireKey, VersionId: version}}}})
		if batchErr != nil {
			requireCloudClientRejection(t, operation, batchErr)
		} else if !cloudBatchRejected(batchOutput, wireKey) {
			t.Fatalf("%s did not return a protection-related per-object rejection: %#v", operation, batchOutput)
		} else {
			t.Logf("denied %s: %s", operation, aws.ToString(batchOutput.Errors[0].Code))
		}
		assertCloudProbe(t, ctx, client, logicalKey, expected, operation)
	}
	// Use different bytes at a distinct source, and prove this same credential
	// can read it. Self-copy can fail for reasons unrelated to immutability.
	sourceObject := objectstore.HashBytes(overwritePayload)
	sourceLogical := "objects/" + sourceObject.BLAKE2b + "/" + randomContractHex(t, 16)
	sourceKey := contractPrefix + "/" + sourceLogical
	if _, err := s3Client.PutObject(ctx, contractPutInput(config, sourceKey, overwritePayload, true)); err != nil {
		t.Fatalf("copy source creation: %v", err)
	}
	var sourceBytes bytes.Buffer
	if err := client.GetVerified(ctx, sourceLogical, sourceObject, &sourceBytes); err != nil || !bytes.Equal(sourceBytes.Bytes(), overwritePayload) {
		t.Fatalf("copy source read positive control failed: %v", err)
	}
	_, copyErr := s3Client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: &config.bucket, Key: &wireKey, CopySource: aws.String(url.PathEscape(config.bucket + "/" + sourceKey))})
	requireCloudClientRejection(t, "copy overwrite", copyErr)
	assertCloudProbe(t, ctx, client, logicalKey, expected, "copy overwrite")

	multipart, multipartErr := s3Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &config.bucket, Key: &wireKey})
	if multipartErr != nil {
		requireCloudClientRejection(t, "multipart overwrite initiation", multipartErr)
	} else {
		if multipart == nil || multipart.UploadId == nil {
			t.Fatal("multipart overwrite initiation returned no upload ID")
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, err := s3Client.AbortMultipartUpload(cleanupCtx, &s3.AbortMultipartUploadInput{Bucket: &config.bucket, Key: &wireKey, UploadId: multipart.UploadId})
			if err != nil {
				// AWS may deny abort permission; R2 locks also block aborts
				// of attempted overwrites. Retain the tiny unfinished probe,
				// never unlock a protected bucket merely to clean up a test.
				requireCloudClientRejection(t, "abort multipart probe", err)
				t.Logf("retained incomplete multipart probe: s3://%s/%s upload-id=%s", config.bucket, wireKey, aws.ToString(multipart.UploadId))
			}
			assertCloudProbe(t, cleanupCtx, client, logicalKey, expected, "abort multipart probe")
		}()
		partPayload := []byte("malicious multipart overwrite")
		part, partErr := s3Client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &config.bucket, Key: &wireKey, UploadId: multipart.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader(partPayload)})
		if partErr != nil {
			requireCloudClientRejection(t, "multipart overwrite part", partErr)
		} else {
			if part == nil || part.ETag == nil {
				t.Fatal("multipart overwrite part returned no ETag")
			}
			_, completeErr := s3Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &config.bucket, Key: &wireKey, UploadId: multipart.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1)}}}})
			requireCloudClientRejection(t, "multipart overwrite completion", completeErr)
		}
	}
	assertCloudProbe(t, ctx, client, logicalKey, expected, "multipart overwrite")

	if config.kind == format.MirrorAWSS3 {
		runAWSControlPlaneProtectionContract(t, ctx, config, s3Client, client, logicalKey, expected)
		runAWSAuthorityProtectionContract(t, ctx, config, client, logicalKey, expected)
	}
	t.Run("real CLI round-trip", func(t *testing.T) { runCloudRoundTrip(t, config) })
}

func runAWSCreateProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, s3Client *s3.Client) {
	t.Helper()
	payload := []byte("default SSE-S3 upload")
	object := objectstore.HashBytes(payload)
	key := strings.Trim(config.prefix, "/") + "/contract-default-encryption-" + randomContractHex(t, 8) + "/objects/" + object.BLAKE2b + "/" + randomContractHex(t, 16)
	key = strings.TrimPrefix(key, "/")
	input := contractPutInput(config, key, payload, true)
	input.ServerSideEncryption = ""
	if _, err := s3Client.PutObject(ctx, input); err != nil {
		t.Fatalf("AWS default-encryption create failed: %v", err)
	}
	head, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &config.bucket, Key: &key})
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
		setContractSSECustomerKey(input)
		_, err := s3Client.PutObject(ctx, input)
		requireCloudHTTPStatus(t, "SSE-C", err, http.StatusForbidden)
		assertCloudKeyAbsent(t, ctx, s3Client, config.bucket, key, "SSE-C")
	})
}

func runAWSControlPlaneProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, s3Client *s3.Client, client *objectstore.Client, probeKey string, expected objectstore.Object) {
	t.Helper()
	assertDenied := func(operation string, err error) {
		t.Helper()
		requireCloudHTTPStatus(t, operation, err, http.StatusForbidden)
		assertCloudProbe(t, ctx, client, probeKey, expected, operation)
	}
	_, err := s3Client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &config.bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusSuspended}})
	assertDenied("suspend bucket versioning", err)
	_, err = s3Client.PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{Bucket: &config.bucket, ObjectLockConfiguration: &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled}})
	assertDenied("alter object-lock configuration", err)
	publicAccess := &types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(false), IgnorePublicAcls: aws.Bool(false), BlockPublicPolicy: aws.Bool(false), RestrictPublicBuckets: aws.Bool(false)}
	_, err = s3Client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: &config.bucket, PublicAccessBlockConfiguration: publicAccess})
	assertDenied("weaken public-access blocking", err)
	_, err = s3Client.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &config.bucket})
	assertDenied("delete public-access blocking", err)
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`, config.bucket, config.bucket)
	_, err = s3Client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &config.bucket, Policy: &policy})
	assertDenied("replace bucket policy", err)
	_, err = s3Client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: &config.bucket})
	assertDenied("delete bucket policy", err)
	_, err = s3Client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{Bucket: &config.bucket})
	assertDenied("delete bucket encryption", err)
	_, err = s3Client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{Bucket: &config.bucket, ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{Rules: []types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAwsKms}}}}})
	assertDenied("replace bucket encryption", err)
	_, err = s3Client.PutBucketAcl(ctx, &s3.PutBucketAclInput{Bucket: &config.bucket, ACL: types.BucketCannedACLPrivate})
	assertDenied("alter bucket ACL", err)
	_, err = s3Client.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{Bucket: &config.bucket})
	assertDenied("delete bucket lifecycle policy", err)
	_, err = s3Client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{Bucket: &config.bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{ID: aws.String("malicious-expiry"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{}, Expiration: &types.LifecycleExpiration{Days: aws.Int32(1)}}}}})
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

func runR2LockProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, client *objectstore.Client, probeKey string, expected objectstore.Object) {
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
	if auditToken == config.credential.AccessKeyID || auditToken == config.credential.SecretAccessKey {
		t.Fatal("R2 lock-audit token must be distinct from all S3 credential values")
	}
	endpoint := "https://api.cloudflare.com/client/v4/accounts/" + accountID + "/r2/buckets/" + url.PathEscape(config.bucket) + "/lock"
	jurisdiction := os.Getenv("BACKUP_R2_CONTRACT_JURISDICTION")
	before := getR2LockRules(t, ctx, endpoint, auditToken, jurisdiction)
	if err := validateR2LockCoverage(config, before.Result.Rules); err != nil {
		t.Fatal(err)
	}
	accountEndpoint := "https://api.cloudflare.com/client/v4/accounts/" + accountID
	bucketEndpoint := strings.TrimSuffix(endpoint, "/lock")
	// Even a valid token-creation request confined to this bucket must fail:
	// ordinary object credentials must not acquire credential-issuing authority.
	tokenBody, err := json.Marshal(map[string]interface{}{
		"name": "backup-testing-contract-token-" + randomContractHex(t, 8),
		"policies": []interface{}{map[string]interface{}{
			"effect":            "allow",
			"resources":         map[string]string{"com.cloudflare.edge.r2.bucket." + accountID + "_" + environmentOrDefault("BACKUP_R2_CONTRACT_JURISDICTION", "default") + "_" + config.bucket: "*"},
			"permission_groups": []interface{}{map[string]string{"id": "2efd5506f9c8494dacb1fa10a3e7d5b6"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []struct{ label, token string }{
		{"access-key ID", config.credential.AccessKeyID}, {"secret access key", config.credential.SecretAccessKey},
	} {
		for _, attack := range []struct{ name, method, endpoint, body string }{
			{"read lock configuration", http.MethodGet, endpoint, ""},
			{"remove bucket locks", http.MethodPut, endpoint, `{"rules":[]}`},
			{"install destructive lifecycle", http.MethodPut, bucketEndpoint + "/lifecycle", `{"rules":[{"id":"backup-testing-expiry","enabled":true,"conditions":{"prefix":""},"deleteObjectsTransition":{"condition":{"type":"Age","maxAge":86400}}}]}`},
			{"enable public managed domain", http.MethodPut, bucketEndpoint + "/domains/managed", `{"enabled":true}`},
			{"delete bucket", http.MethodDelete, bucketEndpoint, ""},
			{"issue account token", http.MethodPost, accountEndpoint + "/tokens", string(tokenBody)},
			{"change own token policy", http.MethodPut, accountEndpoint + "/tokens/" + config.credential.AccessKeyID, string(tokenBody)},
		} {
			status, body, err := doR2ControlRequest(ctx, attack.method, attack.endpoint, credential.token, jurisdiction, []byte(attack.body))
			if err != nil {
				t.Fatalf("R2 %s with %s: %v", attack.name, credential.label, err)
			}
			if !r2ControlDenied(status, body) {
				t.Fatalf("R2 %s with %s did not return a recognized authentication/authorization denial: HTTP %d", attack.name, credential.label, status)
			}
			assertCloudProbe(t, ctx, client, probeKey, expected, "R2 "+attack.name)
			t.Logf("denied R2 %s with %s: HTTP %d; probe unchanged", attack.name, credential.label, status)
		}
	}
	after := getR2LockRules(t, ctx, endpoint, auditToken, jurisdiction)
	beforeRules, _ := json.Marshal(before.Result.Rules)
	afterRules, _ := json.Marshal(after.Result.Rules)
	if !bytes.Equal(beforeRules, afterRules) {
		t.Fatal("R2 lock rules changed during ordinary-credential mutation tests")
	}
}

func validateR2LockCoverage(config cloudContractConfig, rules []json.RawMessage) error {
	// Match the actual object-key namespace, never the narrower probe prefix.
	// An empty configured prefix means the entire bucket, not keys under "/".
	wirePrefix := config.prefix
	if wirePrefix != "" {
		wirePrefix += "/"
	}
	covered := false
	for _, raw := range rules {
		var rule r2LockRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			return fmt.Errorf("decode R2 lock rule: %w", err)
		}
		if rule.ID == "" || rule.Condition.Type == "" {
			return fmt.Errorf("R2 lock audit returned a malformed rule")
		}
		if rule.Enabled && rule.Condition.Type == "Indefinite" && strings.HasPrefix(wirePrefix, rule.Prefix) {
			covered = true
		}
	}
	if !covered {
		return fmt.Errorf("no enabled indefinite R2 lock rule covers backup namespace %q", wirePrefix)
	}
	return nil
}

func getR2LockRules(t *testing.T, ctx context.Context, endpoint, token, jurisdiction string) r2LockEnvelope {
	t.Helper()
	status, data, err := doR2ControlRequest(ctx, http.MethodGet, endpoint, token, jurisdiction, nil)
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

func doR2ControlAttempt(ctx context.Context, method, endpoint, token, jurisdiction string, body []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPut || method == http.MethodPost {
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
	var api smithy.APIError
	if !ok || !errors.As(err, &api) {
		return status, false
	}
	switch status {
	case http.StatusForbidden:
		return status, api.ErrorCode() == "AccessDenied"
	case http.StatusConflict:
		return status, api.ErrorCode() == "ObjectLockedByBucketPolicy"
	case http.StatusPreconditionFailed:
		return status, api.ErrorCode() == "PreconditionFailed"
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
	t.Logf("denied %s: HTTP %d", operation, status)
}

func requireCloudHTTPStatus(t *testing.T, operation string, err error, allowed ...int) {
	t.Helper()
	status, ok := cloudHTTPStatus(err)
	if !ok {
		t.Fatalf("%s did not return a provider HTTP rejection: %v", operation, err)
	}
	for _, expected := range allowed {
		if status == expected {
			if status == http.StatusForbidden {
				requireCloudClientRejection(t, operation, err)
			} else {
				t.Logf("denied %s: HTTP %d", operation, status)
			}
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
		code     string
		accepted bool
	}{
		{403, "AccessDenied", true},
		{409, "ObjectLockedByBucketPolicy", true},
		{412, "PreconditionFailed", true},
		{400, "InvalidArgument", false},
		{403, "SignatureDoesNotMatch", false},
		{403, "InvalidAccessKeyId", false},
		{405, "MethodNotAllowed", false},
		{409, "OperationAborted", false},
		{409, "BucketNotEmpty", false},
		{412, "UnknownError", false},
		{429, "SlowDown", false},
		{500, "InternalError", false},
	} {
		err := &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: test.status}},
			Err:      &smithy.GenericAPIError{Code: test.code, Message: "provider response"},
		}
		status, accepted := cloudClientRejection(err)
		if status != test.status || accepted != test.accepted {
			t.Fatalf("status %d rejection=%t, want status %d rejection %t", status, accepted, test.status, test.accepted)
		}
	}
}

func assertCloudKeyAbsent(t *testing.T, ctx context.Context, client *s3.Client, bucket, key, operation string) {
	t.Helper()
	_, err := client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &bucket, Key: &key})
	if err == nil {
		t.Fatalf("key created by rejected %s", operation)
	}
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response.HTTPStatusCode() != http.StatusNotFound {
		t.Fatalf("could not prove key absence after %s: %v", operation, err)
	}
}

func assertCloudProbe(t *testing.T, ctx context.Context, client *objectstore.Client, key string, expected objectstore.Object, operation string) {
	t.Helper()
	if err := client.Audit(ctx, key, expected); err != nil {
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

// Match observed Cloudflare authentication errors, including the token API's
// nested invalid-Authorization-header code. Generic 400s/invalid bodies are not
// evidence of a credential boundary; timeouts and server errors also fail.
func r2ControlDenied(status int, data []byte) bool {
	var response struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code  int `json:"code"`
			Chain []struct {
				Code int `json:"code"`
			} `json:"error_chain"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(data, &response) != nil || response.Success || len(response.Errors) != 1 || string(response.Result) != "null" {
		return false
	}
	failure := response.Errors[0]
	switch status {
	case http.StatusBadRequest:
		return failure.Code == 9106 || failure.Code == 6003 && len(failure.Chain) == 1 && failure.Chain[0].Code == 6111
	case http.StatusUnauthorized, http.StatusForbidden:
		return failure.Code == 10000 || failure.Code == 9109
	default:
		return false
	}
}

func doR2ControlRequest(ctx context.Context, method, endpoint, token, jurisdiction string, body []byte) (int, []byte, error) {
	// Authentication-negative probes can hit Cloudflare's invalid-token limiter.
	// Retry only throttling, never count it as denial, and retain a bounded wait.
	for attempt := 0; ; attempt++ {
		status, data, err := doR2ControlAttempt(ctx, method, endpoint, token, jurisdiction, body)
		if err != nil || status != http.StatusTooManyRequests || attempt == 4 {
			return status, data, err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 15 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func cloudBatchRejected(output *s3.DeleteObjectsOutput, key string) bool {
	if output == nil || len(output.Errors) != 1 || len(output.Deleted) != 0 || aws.ToString(output.Errors[0].Key) != key {
		return false
	}
	code := aws.ToString(output.Errors[0].Code)
	return code == "AccessDenied" || code == "ObjectLockedByBucketPolicy"
}

func TestCloudBatchRejectionRequiresProtectionEvidence(t *testing.T) {
	for _, code := range []string{"AccessDenied", "ObjectLockedByBucketPolicy", "InvalidArgument", "NoSuchKey", "InternalError", ""} {
		output := &s3.DeleteObjectsOutput{Errors: []types.Error{{Key: aws.String("probe"), Code: &code}}}
		want := code == "AccessDenied" || code == "ObjectLockedByBucketPolicy"
		if got := cloudBatchRejected(output, "probe"); got != want {
			t.Fatalf("batch code %q accepted=%t, want %t", code, got, want)
		}
	}
	if cloudBatchRejected(nil, "probe") || cloudBatchRejected(&s3.DeleteObjectsOutput{}, "probe") {
		t.Fatal("empty result accepted")
	}
}
