package integration

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"backup/internal/objectstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

func setContractSSECustomerKey(input *s3.PutObjectInput) {
	key := bytes.Repeat([]byte{0x42}, 32)
	digest := md5.Sum(key)
	input.SSECustomerAlgorithm = aws.String("AES256")
	input.SSECustomerKey = aws.String(base64.StdEncoding.EncodeToString(key))
	input.SSECustomerKeyMD5 = aws.String(base64.StdEncoding.EncodeToString(digest[:]))
}

func requireCloudAPIError(t *testing.T, operation string, err error, status int, code string) {
	t.Helper()
	requireCloudHTTPStatus(t, operation, err, status)
	var api smithy.APIError
	if !errors.As(err, &api) || api.ErrorCode() != code {
		t.Fatalf("%s did not return %s: %v", operation, code, err)
	}
	t.Logf("denied %s: HTTP %d %s", operation, status, code)
}

// Use the SDK's independent SigV4 signer for the small IAM/STS Query surface;
// no ambient SDK configuration or administrator credential reaches this client.
func cloudQuery(ctx context.Context, config cloudContractConfig, service string, values url.Values) (int, []byte, error) {
	if service != "iam" && service != "sts" {
		return 0, nil, fmt.Errorf("unsupported authority service")
	}
	body := values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+service+".amazonaws.com/", strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	digest := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(ctx, config.credential, request, hex.EncodeToString(digest[:]), service, "us-east-1", time.Now()); err != nil {
		return 0, nil, err
	}
	response, err := contractHTTPClient().Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if len(data) > 1<<20 {
		return 0, nil, fmt.Errorf("authority response exceeds bound")
	}
	return response.StatusCode, data, err
}

func runAWSAuthorityProtectionContract(t *testing.T, ctx context.Context, config cloudContractConfig, client objectstore.Store, probeKey string, expected objectstore.Object) {
	t.Helper()
	user := os.Getenv("BACKUP_AWS_CONTRACT_USER")
	if !regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`).MatchString(user) {
		t.Fatal("BACKUP_AWS_CONTRACT_USER must identify the ordinary IAM user under test")
	}
	status, data, err := cloudQuery(ctx, config, "sts", url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}})
	if err != nil || status != http.StatusOK {
		t.Fatalf("identify ordinary AWS client: HTTP %d error=%v", status, err)
	}
	var identity struct {
		Result struct {
			ARN string `xml:"Arn"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := xml.Unmarshal(data, &identity); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(identity.Result.ARN, ":user/") || !strings.HasSuffix(identity.Result.ARN, "/"+user) {
		t.Fatalf("ordinary AWS caller is not the configured IAM user: %q", identity.Result.ARN)
	}
	// Granting only the task bucket's administration is enough to attack its
	// immutability. Never attempt account-wide AdministratorAccess attachment.
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`, config.bucket, config.bucket)
	for _, values := range []url.Values{
		{"Action": {"PutUserPolicy"}, "PolicyName": {"backup-contract-" + randomContractHex(t, 8)}, "PolicyDocument": {policy}},
		{"Action": {"CreateAccessKey"}},
	} {
		values.Set("Version", "2010-05-08")
		values.Set("UserName", user)
		status, data, err := cloudQuery(ctx, config, "iam", values)
		if err != nil {
			t.Fatal(err)
		}
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		if err := xml.Unmarshal(data, &failure); err != nil || status != http.StatusForbidden || failure.Error.Code != "AccessDenied" {
			t.Fatalf("IAM %s was not denied by authorization: HTTP %d code=%q decode=%v", values.Get("Action"), status, failure.Error.Code, err)
		}
		assertCloudProbe(t, ctx, client, probeKey, expected, "IAM "+values.Get("Action"))
		t.Logf("denied IAM %s on ordinary user; probe unchanged", values.Get("Action"))
	}
}
