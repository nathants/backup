package s3server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const aws4Algorithm = "AWS4-HMAC-SHA256"

var emptySHA256 = hex.EncodeToString(sha256.New().Sum(nil))

type credentialScope struct {
	AccessKey string
	Date      string
	Region    string
	Service   string
}

func (scope credentialScope) String() string {
	return scope.Date + "/" + scope.Region + "/" + scope.Service + "/aws4_request"
}

type parsedAuthorization struct {
	Scope        credentialScope
	Signature    string
	SignedNames  []string
	SignedLookup map[string]struct{}
}

func parseAuthorization(value string) (parsedAuthorization, error) {
	if value == "" {
		return parsedAuthorization{}, fmt.Errorf("missing authorization header")
	}
	prefix := aws4Algorithm + " "
	if !strings.HasPrefix(value, prefix) {
		return parsedAuthorization{}, fmt.Errorf("unsupported authorization algorithm")
	}
	fields := make(map[string]string, 3)
	for _, raw := range strings.Split(strings.TrimPrefix(value, prefix), ",") {
		pair := strings.SplitN(strings.TrimSpace(raw), "=", 2)
		if len(pair) != 2 || pair[0] == "" || pair[1] == "" {
			return parsedAuthorization{}, fmt.Errorf("malformed authorization field")
		}
		if _, exists := fields[pair[0]]; exists {
			return parsedAuthorization{}, fmt.Errorf("duplicate authorization field %q", pair[0])
		}
		fields[pair[0]] = pair[1]
	}
	if len(fields) != 3 {
		return parsedAuthorization{}, fmt.Errorf("authorization must contain Credential, SignedHeaders, and Signature")
	}
	credential, okCredential := fields["Credential"]
	signed, okSigned := fields["SignedHeaders"]
	signature, okSignature := fields["Signature"]
	if !okCredential || !okSigned || !okSignature {
		return parsedAuthorization{}, fmt.Errorf("authorization is missing a required field")
	}
	credentialParts := strings.Split(credential, "/")
	if len(credentialParts) != 5 || credentialParts[4] != "aws4_request" {
		return parsedAuthorization{}, fmt.Errorf("invalid credential scope")
	}
	scope := credentialScope{AccessKey: credentialParts[0], Date: credentialParts[1], Region: credentialParts[2], Service: credentialParts[3]}
	if scope.AccessKey == "" || len(scope.Date) != 8 || scope.Service != "s3" {
		return parsedAuthorization{}, fmt.Errorf("invalid credential scope")
	}
	if len(signature) != sha256.Size*2 {
		return parsedAuthorization{}, fmt.Errorf("invalid signature length")
	}
	if _, err := hex.DecodeString(signature); err != nil || strings.ToLower(signature) != signature {
		return parsedAuthorization{}, fmt.Errorf("signature is not lowercase hexadecimal")
	}
	names := strings.Split(signed, ";")
	lookup := make(map[string]struct{}, len(names))
	for index, name := range names {
		if name == "" || name != strings.ToLower(name) {
			return parsedAuthorization{}, fmt.Errorf("signed header names must be nonempty lowercase strings")
		}
		if index > 0 && names[index-1] >= name {
			return parsedAuthorization{}, fmt.Errorf("signed header names must be sorted uniquely")
		}
		lookup[name] = struct{}{}
	}
	if _, ok := lookup["host"]; !ok {
		return parsedAuthorization{}, fmt.Errorf("host is not signed")
	}
	return parsedAuthorization{Scope: scope, Signature: signature, SignedNames: names, SignedLookup: lookup}, nil
}

func verifySignature(request *http.Request, authorization parsedAuthorization, secret string) error {
	canonical, err := canonicalRequest(request, authorization.SignedNames)
	if err != nil {
		return err
	}
	date := request.Header.Get("x-amz-date")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		aws4Algorithm,
		date,
		authorization.Scope.String(),
		hex.EncodeToString(canonicalDigest[:]),
	}, "\n")
	expected := hmacHex(signingKey(secret, authorization.Scope.Date, authorization.Scope.Region, authorization.Scope.Service), stringToSign)
	actualBytes, _ := hex.DecodeString(authorization.Signature)
	expectedBytes, _ := hex.DecodeString(expected)
	if len(actualBytes) != len(expectedBytes) || subtle.ConstantTimeCompare(actualBytes, expectedBytes) != 1 {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func validateRequestDate(request *http.Request, authorization parsedAuthorization, now time.Time, maximumSkew time.Duration) error {
	dateText := request.Header.Get("x-amz-date")
	if dateText == "" {
		return fmt.Errorf("x-amz-date is required")
	}
	date, err := time.Parse("20060102T150405Z", dateText)
	if err != nil || date.Format("20060102T150405Z") != dateText {
		return fmt.Errorf("x-amz-date is invalid")
	}
	if authorization.Scope.Date != dateText[:8] {
		return fmt.Errorf("credential date does not match x-amz-date")
	}
	if date.Before(now.Add(-maximumSkew)) || date.After(now.Add(maximumSkew)) {
		return fmt.Errorf("request date is outside the allowed window")
	}
	return nil
}

func requireSecurityHeadersSigned(request *http.Request, authorization parsedAuthorization) error {
	required := map[string]struct{}{"host": {}}
	if request.ContentLength > 0 {
		required["content-length"] = struct{}{}
	}
	for name := range request.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			required[lower] = struct{}{}
		}
		switch lower {
		case "content-md5", "if-none-match", "if-match", "if-modified-since", "if-unmodified-since", "if-range", "range", "date":
			required[lower] = struct{}{}
		}
	}
	for name := range required {
		if _, ok := authorization.SignedLookup[name]; !ok {
			return fmt.Errorf("security-relevant header %q is not signed", name)
		}
	}
	return nil
}

func canonicalRequest(request *http.Request, signedNames []string) (string, error) {
	uri, err := canonicalURI(request)
	if err != nil {
		return "", err
	}
	query, err := canonicalQuery(request.URL.RawQuery)
	if err != nil {
		return "", err
	}
	headers, err := canonicalHeaders(request, signedNames)
	if err != nil {
		return "", err
	}
	payloadHash := request.Header.Get("x-amz-content-sha256")
	if !isLowerHex(payloadHash, sha256.Size*2) {
		return "", fmt.Errorf("x-amz-content-sha256 must be a lowercase SHA-256 digest")
	}
	return strings.Join([]string{
		request.Method,
		uri,
		query,
		headers,
		strings.Join(signedNames, ";"),
		payloadHash,
	}, "\n"), nil
}

func canonicalURI(request *http.Request) (string, error) {
	if request.URL.Path == "" || strings.Contains(request.URL.EscapedPath(), "%") || request.URL.EscapedPath() != request.URL.Path {
		return "", fmt.Errorf("encoded or empty request paths are unsupported")
	}
	return request.URL.Path, nil
}

type queryField struct {
	name  string
	value string
}

func canonicalQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parts := strings.Split(raw, "&")
	fields := make([]queryField, 0, len(parts))
	for _, part := range parts {
		pair := strings.SplitN(part, "=", 2)
		name, err := percentDecode(pair[0])
		if err != nil {
			return "", fmt.Errorf("invalid query name encoding")
		}
		value := ""
		if len(pair) == 2 {
			value, err = percentDecode(pair[1])
			if err != nil {
				return "", fmt.Errorf("invalid query value encoding")
			}
		}
		fields = append(fields, queryField{name: awsEncode(name), value: awsEncode(value)})
	}
	sort.Slice(fields, func(left, right int) bool {
		if fields[left].name != fields[right].name {
			return fields[left].name < fields[right].name
		}
		return fields[left].value < fields[right].value
	})
	var output strings.Builder
	for index, field := range fields {
		if index > 0 {
			output.WriteByte('&')
		}
		output.WriteString(field.name)
		output.WriteByte('=')
		output.WriteString(field.value)
	}
	return output.String(), nil
}

func canonicalHeaders(request *http.Request, signedNames []string) (string, error) {
	var output strings.Builder
	for _, name := range signedNames {
		var value string
		switch name {
		case "host":
			value = request.Host
		case "content-length":
			if request.ContentLength < 0 {
				return "", fmt.Errorf("signed content-length is unknown")
			}
			value = fmt.Sprintf("%d", request.ContentLength)
		default:
			values, exists := request.Header[http.CanonicalHeaderKey(name)]
			if !exists {
				return "", fmt.Errorf("signed header %q is absent", name)
			}
			value = strings.Join(values, ",")
		}
		if value == "" {
			return "", fmt.Errorf("signed header %q is empty", name)
		}
		output.WriteString(name)
		output.WriteByte(':')
		output.WriteString(compressHeaderWhitespace(value))
		output.WriteByte('\n')
	}
	return output.String(), nil
}

func percentDecode(value string) (string, error) {
	data := []byte(value)
	decoded := make([]byte, 0, len(data))
	for index := 0; index < len(data); index++ {
		if data[index] != '%' {
			decoded = append(decoded, data[index])
			continue
		}
		if index+2 >= len(data) {
			return "", fmt.Errorf("truncated escape")
		}
		pair, err := hex.DecodeString(string(data[index+1 : index+3]))
		if err != nil {
			return "", err
		}
		decoded = append(decoded, pair[0])
		index += 2
	}
	return string(decoded), nil
}

func awsEncode(value string) string {
	const hexUpper = "0123456789ABCDEF"
	var output strings.Builder
	for _, char := range []byte(value) {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._~", rune(char)) {
			output.WriteByte(char)
			continue
		}
		output.WriteByte('%')
		output.WriteByte(hexUpper[char>>4])
		output.WriteByte(hexUpper[char&0x0f])
	}
	return output.String()
}

func signingKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, service)
	return hmacSHA256(serviceKey, "aws4_request")
}

func hmacHex(key []byte, value string) string {
	return hex.EncodeToString(hmacSHA256(key, value))
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func compressHeaderWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func isLowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
