package backup

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

func NormalizePath(relPath string) (string, error) {
	if relPath == "" {
		return "", fmt.Errorf("empty path")
	}
	relPath = filepath.ToSlash(relPath)
	if strings.HasPrefix(relPath, "/") {
		return "", fmt.Errorf("path must be relative: %q", relPath)
	}
	cleaned := path.Clean(relPath)
	if cleaned == "." {
		return "", fmt.Errorf("path resolves to root: %q", relPath)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path escapes root: %q", relPath)
	}
	if strings.Contains(cleaned, "\x00") || strings.Contains(cleaned, "\n") || strings.Contains(cleaned, "\r") || strings.Contains(cleaned, "\t") {
		return "", fmt.Errorf("path contains invalid characters: %q", relPath)
	}
	if strings.HasPrefix(cleaned, "./") {
		cleaned = strings.TrimPrefix(cleaned, "./")
	}
	if cleaned == "" {
		return "", fmt.Errorf("path resolves to root: %q", relPath)
	}
	return "./" + cleaned, nil
}

func IndexPathToOS(root string, indexPath string) (string, error) {
	// Never trust index.tsv (it may come from an untrusted git remote).
	// Enforce that index paths are in canonical normalized form (./..., no ..).
	if !strings.HasPrefix(indexPath, "./") {
		return "", fmt.Errorf("invalid index path (must start with ./): %q", indexPath)
	}
	rel := strings.TrimPrefix(indexPath, "./")
	normalized, err := NormalizePath(rel)
	if err != nil {
		return "", fmt.Errorf("invalid index path %q: %w", indexPath, err)
	}
	if normalized != indexPath {
		return "", fmt.Errorf("non-canonical index path %q (expected %q)", indexPath, normalized)
	}
	return filepath.Join(root, filepath.FromSlash(rel)), nil
}

func NormalizeTargetPath(root string, target string) (string, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("relative target: %w", err)
	}
	return NormalizePath(rel)
}

func IsWithinRoot(root string, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
