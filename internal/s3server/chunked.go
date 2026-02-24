package s3server

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type chunkSigner struct {
	SeedSignature string
	SigningKey    []byte
	Scope         string
	AmzDate       string
}

// decodeChunks decodes an aws-chunked request body, verifies the SigV4 streaming
// chunk signatures, writes decoded bytes to writer, and returns:
// - total decoded bytes
// - final chunk signature (the 0-sized chunk signature)
// - parsed trailers (lowercased keys)
func decodeChunks(reader io.Reader, writer io.Writer, signer chunkSigner) (int64, string, map[string]string, error) {
	br := bufio.NewReader(reader)
	prevSignature := signer.SeedSignature
	var total int64

	for {
		line, err := readLine(br)
		if err != nil {
			return 0, "", nil, err
		}
		if line == "" {
			return 0, "", nil, fmt.Errorf("empty chunk header")
		}
		parts := strings.Split(line, ";")
		sizeHex := parts[0]
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil || size < 0 {
			return 0, "", nil, fmt.Errorf("invalid chunk size")
		}
		signature, err := chunkSignatureFromHeader(parts[1:])
		if err != nil {
			return 0, "", nil, err
		}

		if size > 0 {
			hash := sha256.New()
			multiWriter := io.MultiWriter(writer, hash)
			written, err := io.CopyN(multiWriter, br, size)
			if err != nil {
				return 0, "", nil, err
			}
			if written != size {
				return 0, "", nil, fmt.Errorf("short chunk read")
			}
			if err := readCRLF(br); err != nil {
				return 0, "", nil, err
			}
			dataHash := fmt.Sprintf("%x", hash.Sum(nil))
			expected := chunkSignatureForHash(signer, prevSignature, dataHash)
			if signature != expected {
				return 0, "", nil, fmt.Errorf("chunk signature mismatch")
			}
			prevSignature = signature
			total += size
			continue
		}

		// Final 0-sized chunk.
		expected := chunkSignatureForHash(signer, prevSignature, emptyChunkHash)
		if signature != expected {
			return 0, "", nil, fmt.Errorf("chunk signature mismatch")
		}
		prevSignature = signature

		trailers, err := readTrailers(br)
		if err != nil {
			return 0, "", nil, err
		}
		return total, prevSignature, trailers, nil
	}
}

func chunkSignatureFromHeader(parts []string) (string, error) {
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "chunk-signature=") {
			return strings.TrimPrefix(part, "chunk-signature="), nil
		}
	}
	return "", fmt.Errorf("missing chunk signature")
}

func chunkSignatureForHash(signer chunkSigner, previous string, dataHash string) string {
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		signer.AmzDate,
		signer.Scope,
		previous,
		emptyChunkHash,
		dataHash,
	}, "\n")
	return hmacHex(signer.SigningKey, stringToSign)
}

func chunkSignatureFor(signer chunkSigner, previous string, data []byte) string {
	dataHash := fmt.Sprintf("%x", sha256.Sum256(data))
	return chunkSignatureForHash(signer, previous, dataHash)
}

func trailerSignatureFor(signer chunkSigner, previous string, trailerPayload string) string {
	payloadHash := fmt.Sprintf("%x", sha256.Sum256([]byte(trailerPayload)))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER",
		signer.AmzDate,
		signer.Scope,
		previous,
		payloadHash,
	}, "\n")
	return hmacHex(signer.SigningKey, stringToSign)
}

func trailerPayload(required string, trailers map[string]string) (string, error) {
	if required == "" {
		return "", fmt.Errorf("missing trailer list")
	}
	var builder strings.Builder
	for _, name := range strings.Split(required, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		value, ok := trailers[name]
		if !ok {
			return "", fmt.Errorf("missing trailer %s", name)
		}
		builder.WriteString(name)
		builder.WriteString(":")
		builder.WriteString(strings.TrimSpace(value))
		builder.WriteString("\n")
	}
	return builder.String(), nil
}

func readTrailers(br *bufio.Reader) (map[string]string, error) {
	trailers := map[string]string{}
	for {
		line, err := readLine(br)
		if err != nil {
			if err == io.EOF {
				return trailers, nil
			}
			return nil, err
		}
		if line == "" {
			return trailers, nil
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid trailer")
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		trailers[name] = value
	}
}

func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if err == io.EOF && line == "" {
		return "", io.EOF
	}
	return line, nil
}

func readCRLF(br *bufio.Reader) error {
	first, err := br.ReadByte()
	if err != nil {
		return err
	}
	if first == '\n' {
		return nil
	}
	if first != '\r' {
		return fmt.Errorf("missing chunk terminator")
	}
	second, err := br.ReadByte()
	if err != nil {
		return err
	}
	if second != '\n' {
		return fmt.Errorf("missing chunk terminator")
	}
	return nil
}

