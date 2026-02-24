package backup

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Root           string
	GitRemote      string
	S3Bucket       string
	S3Prefix       string
	S3Endpoint     string
	S3Region       string
	S3InsecureTLS  bool
	ChunkSizeBytes int64
}

type Requirements struct {
	NeedRoot bool
	NeedGit  bool
	NeedS3   bool
}

func LoadConfig(req Requirements) (Config, error) {
	config := Config{
		ChunkSizeBytes: 100 * 1024 * 1024,
		S3Region:       "us-east-1",
	}

	if req.NeedRoot {
		root := strings.TrimSpace(os.Getenv("BACKUP_ROOT"))
		if root == "" {
			return config, fmt.Errorf("BACKUP_ROOT must be set")
		}
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return config, fmt.Errorf("resolve BACKUP_ROOT: %w", err)
		}
		config.Root = absRoot
	}

	if req.NeedGit {
		gitRemote := strings.TrimSpace(os.Getenv("BACKUP_GIT"))
		if gitRemote == "" {
			return config, fmt.Errorf("BACKUP_GIT must be set")
		}
		config.GitRemote = gitRemote
	}

	if req.NeedS3 {
		s3URL := strings.TrimSpace(os.Getenv("BACKUP_S3"))
		if s3URL == "" {
			return config, fmt.Errorf("BACKUP_S3 must be set")
		}
		parsed, err := url.Parse(s3URL)
		if err != nil {
			return config, fmt.Errorf("parse BACKUP_S3: %w", err)
		}
		if parsed.Scheme != "s3" {
			return config, fmt.Errorf("BACKUP_S3 must use s3:// scheme")
		}
		if parsed.Host == "" {
			return config, fmt.Errorf("BACKUP_S3 must include bucket")
		}
		prefix := strings.TrimPrefix(parsed.Path, "/")
		prefix = path.Clean("/" + prefix)
		prefix = strings.TrimPrefix(prefix, "/")
		if prefix == "." {
			prefix = ""
		}
		config.S3Bucket = parsed.Host
		config.S3Prefix = prefix
	}

	if value := strings.TrimSpace(os.Getenv("BACKUP_CHUNK_MEGABYTES")); value != "" {
		chunkMegabytes, err := strconv.Atoi(value)
		if err != nil || chunkMegabytes <= 0 {
			return config, fmt.Errorf("BACKUP_CHUNK_MEGABYTES must be a positive integer")
		}
		config.ChunkSizeBytes = int64(chunkMegabytes) * 1024 * 1024
	}

	config.S3Endpoint = strings.TrimSpace(os.Getenv("BACKUP_S3_ENDPOINT"))
	if value := strings.TrimSpace(os.Getenv("BACKUP_S3_REGION")); value != "" {
		config.S3Region = value
	}
	if value := strings.TrimSpace(os.Getenv("BACKUP_S3_INSECURE_TLS")); value != "" {
		config.S3InsecureTLS = parseBool(value)
	}

	return config, nil
}

func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func (config Config) BackupDir() string {
	return filepath.Join(config.Root, ".backup")
}
