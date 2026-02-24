package backup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
)

type S3Client struct {
	client *s3.Client
}

func NewS3Client(config Config) (*S3Client, error) {
	ctx := context.Background()
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...any) (aws.Endpoint, error) {
		if config.S3Endpoint != "" && service == s3.ServiceID {
			return aws.Endpoint{
				URL:               config.S3Endpoint,
				SigningRegion:     config.S3Region,
				HostnameImmutable: true,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(config.S3Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN"))),
		awsconfig.WithEndpointResolverWithOptions(resolver),
	)
	if err != nil {
		return nil, err
	}
	if config.S3InsecureTLS {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		awsConfig.HTTPClient = &http.Client{Transport: transport}
	}
	awsConfig.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.UsePathStyle = true
		options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
			_, err := stack.Finalize.Remove((&v4.UnsignedPayload{}).ID())
			if err != nil {
				return err
			}
			return stack.Finalize.Insert(&v4.ComputePayloadSHA256{}, "ResolveEndpointV2", middleware.After)
		})

	})
	return &S3Client{client: client}, nil
}

func (client *S3Client) PutObject(ctx context.Context, bucket string, key string, body io.ReadSeeker) (int64, string, error) {
	hash := sha256.New()
	size, err := io.Copy(hash, body)
	if err != nil {
		return 0, "", err
	}
	_, err = body.Seek(0, 0)
	if err != nil {
		return 0, "", err
	}
	payloadHash := fmt.Sprintf("%x", hash.Sum(nil))
	ctx = v4.SetPayloadHash(ctx, payloadHash)
	_, err = client.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   body,
	})
	if err != nil {
		return 0, "", err
	}
	return size, payloadHash, nil
}

func (client *S3Client) GetObject(ctx context.Context, bucket string, key string) (io.ReadCloser, error) {
	emptyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	ctx = v4.SetPayloadHash(ctx, emptyHash)
	output, err := client.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return output.Body, nil
}

func ObjectKey(prefix string, packName string) string {
	if prefix == "" {
		return packName
	}
	return path.Join(prefix, packName)
}

func ParseS3URL(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if parsed.Scheme != "s3" {
		return "", "", fmt.Errorf("s3 url must start with s3://")
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("s3 url must include bucket")
	}
	prefix := strings.TrimPrefix(parsed.Path, "/")
	prefix = path.Clean("/" + prefix)
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix == "." {
		prefix = ""
	}
	return parsed.Host, prefix, nil
}

func ReadFileSeek(path string) (io.ReadSeeker, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}
