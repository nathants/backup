package s3server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	streamingPayload        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingPayloadTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	aws4Algorithm           = "AWS4-HMAC-SHA256"
)

var emptySHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("")))

var emptyChunkHash = fmt.Sprintf("%x", sha256.Sum256([]byte("")))

type credentialScope struct {
	AccessKey string
	Date      string
	Region    string
	Service   string
}

func (scope credentialScope) String() string {
	return fmt.Sprintf("%s/%s/%s/aws4_request", scope.Date, scope.Region, scope.Service)
}

func parseAuthorization(value string) (credentialScope, string, []string, error) {
	if value == "" {
		return credentialScope{}, "", nil, fmt.Errorf("missing authorization header")
	}
	if !strings.HasPrefix(value, aws4Algorithm+" ") {
		return credentialScope{}, "", nil, fmt.Errorf("invalid authorization header")
	}
	parts := strings.Split(value[len(aws4Algorithm)+1:], ",")
	fields := map[string]string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return credentialScope{}, "", nil, fmt.Errorf("invalid authorization field")
		}
		fields[keyValue[0]] = keyValue[1]
	}
	credentialRaw, ok := fields["Credential"]
	if !ok {
		return credentialScope{}, "", nil, fmt.Errorf("missing credential")
	}
	credParts := strings.Split(credentialRaw, "/")
	if len(credParts) != 5 {
		return credentialScope{}, "", nil, fmt.Errorf("invalid credential scope")
	}
	if credParts[4] != "aws4_request" {
		return credentialScope{}, "", nil, fmt.Errorf("invalid credential scope")
	}
	credential := credentialScope{
		AccessKey: credParts[0],
		Date:      credParts[1],
		Region:    credParts[2],
		Service:   credParts[3],
	}
	signedHeadersRaw, ok := fields["SignedHeaders"]
	if !ok {
		return credentialScope{}, "", nil, fmt.Errorf("missing signed headers")
	}
	signature, ok := fields["Signature"]
	if !ok {
		return credentialScope{}, "", nil, fmt.Errorf("missing signature")
	}
	return credential, signature, strings.Split(signedHeadersRaw, ";"), nil
}

func canonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) (string, error) {
	canonicalURI, err := canonicalURI(r.URL)
	if err != nil {
		return "", err
	}
	canonicalQuery, err := canonicalQuery(r.URL)
	if err != nil {
		return "", err
	}
	canonicalHeaders, err := canonicalHeaders(r, signedHeaders)
	if err != nil {
		return "", err
	}
	signedHeadersLower := make([]string, len(signedHeaders))
	for i, header := range signedHeaders {
		signedHeadersLower[i] = strings.ToLower(header)
	}
	canonical := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		strings.Join(signedHeadersLower, ";"),
		payloadHash,
	}, "\n")
	return canonical, nil
}

func stringToSign(r *http.Request, scope string, canonicalRequest string) (string, error) {
	date := strings.TrimSpace(r.Header.Get("x-amz-date"))
	if date == "" {
		return "", fmt.Errorf("missing x-amz-date")
	}
	hash := sha256.Sum256([]byte(canonicalRequest))
	return strings.Join([]string{
		aws4Algorithm,
		date,
		scope,
		fmt.Sprintf("%x", hash[:]),
	}, "\n"), nil
}

func canonicalHeaders(r *http.Request, signedHeaders []string) (string, error) {
	var lines []string
	for _, header := range signedHeaders {
		name := strings.ToLower(header)
		var value string
		if name == "host" {
			value = r.Host
		} else {
			values, ok := r.Header[http.CanonicalHeaderKey(name)]
			if !ok {
				return "", fmt.Errorf("missing signed header %s", name)
			}
			value = strings.Join(values, ",")
		}
		value = compressSpaces(strings.TrimSpace(value))
		lines = append(lines, fmt.Sprintf("%s:%s", name, value))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func canonicalURI(u *url.URL) (string, error) {
	var uriPath string
	if len(u.Opaque) > 0 {
		const schemeSeparator = "//"
		const pathSeparator = "/"
		const queryStart = "?"
		opaque := u.Opaque
		if index := strings.Index(opaque, queryStart); index >= 0 {
			opaque = opaque[:index]
		}
		if strings.HasPrefix(opaque, schemeSeparator) {
			opaque = opaque[len(schemeSeparator):]
		}
		if index := strings.Index(opaque, pathSeparator); index >= 0 {
			uriPath = opaque[index:]
		}
	} else {
		uriPath = u.EscapedPath()
	}
	if uriPath == "" {
		uriPath = "/"
	}
	return uriPath, nil
}

func canonicalQuery(u *url.URL) (string, error) {
	if u.RawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		vals := values[key]
		sort.Strings(vals)
		for _, value := range vals {
			parts = append(parts, uriEncode(key)+"="+uriEncode(value))
		}
	}
	return strings.Join(parts, "&"), nil
}

func signingKey(secret string, date string, region string, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacHex(key []byte, value string) string {
	return hex.EncodeToString(hmacSHA256(key, value))
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func compressSpaces(value string) string {
	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

func uriEncode(value string) string {
	value = url.QueryEscape(value)
	value = strings.ReplaceAll(value, "+", "%20")
	return value
}
