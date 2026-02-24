package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type StagingManifest struct {
	Packs []StagedPack `json:"packs"`
}

type StagedPack struct {
	PackKey    string   `json:"pack_key"`
	CipherHash string   `json:"cipher_hash"`
	CipherSize int64    `json:"cipher_size"`
	CreatedUTC string   `json:"created_utc"`
	Hashes     []string `json:"hashes"`
	Path       string   `json:"path"`
}

func stagingDir(root string) string {
	return filepath.Join(root, ".backup", "staging")
}

func stagingManifestPath(root string) string {
	return filepath.Join(stagingDir(root), "manifest.json")
}

func ReadStaging(root string) (StagingManifest, error) {
	path := stagingManifestPath(root)
	data, err := os.ReadFile(path)
	if err != nil {
		return StagingManifest{}, err
	}
	var manifest StagingManifest
	err = json.Unmarshal(data, &manifest)
	if err != nil {
		return StagingManifest{}, err
	}
	return manifest, nil
}

func WriteStaging(root string, manifest StagingManifest) error {
	path := stagingManifestPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func RemoveStaging(root string) error {
	return os.RemoveAll(stagingDir(root))
}
