package format

import (
	"bytes"
	"fmt"
	"io"
)

const (
	BundleFull        = "full"
	BundleIncremental = "incremental"

	MaximumMetadataManifestBytes = 1 << 20
	// Every valid part row is at least 271 bytes, so no manifest under the
	// wire-size ceiling can contain more part records than this.
	MaximumMetadataManifestParts = MaximumMetadataManifestBytes / 271
)

type ManifestPart struct {
	Number   uint32
	Count    uint32
	ObjectID string
	Hash     string
	SHA256   string
	MD5      string
	Size     uint64
}

type MetadataManifest struct {
	RepositoryUUID string
	Sequence       uint64
	BaseCommit     string
	TipCommit      string
	Kind           string
	BundleHash     string
	BundleSize     uint64
	Parts          []ManifestPart
}

func (manifest MetadataManifest) MarshalText() ([]byte, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	rows := [][]string{
		{"repository-uuid", manifest.RepositoryUUID},
		{"manifest-format", "1"},
		{"sequence", uintText(manifest.Sequence)},
		{"base-commit", manifest.BaseCommit},
		{"tip-commit", manifest.TipCommit},
		{"kind", manifest.Kind},
		{"bundle-blake2b", manifest.BundleHash},
		{"bundle-size", uintText(manifest.BundleSize)},
		{"part-count", uintText(uint64(len(manifest.Parts)))},
	}
	for _, part := range manifest.Parts {
		rows = append(rows, []string{"part", uintText(uint64(part.Number)), uintText(uint64(part.Count)), part.ObjectID, part.Hash, part.SHA256, part.MD5, uintText(part.Size)})
	}
	data, err := marshalRows(rows)
	if err != nil {
		return nil, err
	}
	if len(data) > MaximumMetadataManifestBytes {
		return nil, fmt.Errorf("metadata manifest exceeds %d bytes", MaximumMetadataManifestBytes)
	}
	return data, nil
}

func (manifest *MetadataManifest) UnmarshalText(data []byte) error {
	if manifest == nil {
		return fmt.Errorf("cannot unmarshal metadata manifest into nil receiver")
	}
	limits := DefaultLimits()
	limits.MaxFileBytes = MaximumMetadataManifestBytes
	limits.MaxRecords = 9 + MaximumMetadataManifestParts
	parsed, err := ParseMetadataManifest(bytes.NewReader(data), limits)
	if err != nil {
		return err
	}
	*manifest = parsed
	return nil
}

func ParseMetadataManifest(reader io.Reader, limits Limits) (MetadataManifest, error) {
	if limits.MaxFileBytes > MaximumMetadataManifestBytes {
		limits.MaxFileBytes = MaximumMetadataManifestBytes
	}
	if limits.MaxRecords > 9+MaximumMetadataManifestParts {
		limits.MaxRecords = 9 + MaximumMetadataManifestParts
	}
	rows, err := readRows(reader, limits)
	if err != nil {
		return MetadataManifest{}, fmt.Errorf("metadata manifest: %w", err)
	}
	if len(rows) < 10 {
		return MetadataManifest{}, fmt.Errorf("metadata manifest has %d records, expected at least 10", len(rows))
	}
	tags := []string{"repository-uuid", "manifest-format", "sequence", "base-commit", "tip-commit", "kind", "bundle-blake2b", "bundle-size", "part-count"}
	for index, tag := range tags {
		if err := requireFieldCount(rows[index], 2, index+1); err != nil {
			return MetadataManifest{}, fmt.Errorf("metadata manifest: %w", err)
		}
		if rows[index][0] != tag {
			return MetadataManifest{}, fmt.Errorf("metadata manifest record %d is %q, expected %q", index+1, rows[index][0], tag)
		}
	}
	if rows[1][1] != "1" {
		return MetadataManifest{}, fmt.Errorf("unsupported metadata manifest format %q", rows[1][1])
	}
	sequence, err := parseUint(rows[2][1], 64, "sequence")
	if err != nil {
		return MetadataManifest{}, err
	}
	bundleSize, err := parseUint(rows[7][1], 64, "bundle size")
	if err != nil {
		return MetadataManifest{}, err
	}
	partCount, err := parseUint(rows[8][1], 32, "part count")
	if err != nil {
		return MetadataManifest{}, err
	}
	if partCount == 0 || partCount > uint64(limits.MaxRecords-9) || len(rows) != 9+int(partCount) {
		return MetadataManifest{}, fmt.Errorf("metadata manifest part count %d disagrees with %d part records", partCount, len(rows)-9)
	}
	manifest := MetadataManifest{
		RepositoryUUID: rows[0][1], Sequence: sequence, BaseCommit: rows[3][1], TipCommit: rows[4][1],
		Kind: rows[5][1], BundleHash: rows[6][1], BundleSize: bundleSize,
		Parts: make([]ManifestPart, 0, partCount),
	}
	for rowIndex, row := range rows[9:] {
		record := rowIndex + 10
		if err := requireFieldCount(row, 8, record); err != nil {
			return MetadataManifest{}, fmt.Errorf("metadata manifest: %w", err)
		}
		if row[0] != "part" {
			return MetadataManifest{}, fmt.Errorf("metadata manifest record %d has unknown tag %q", record, row[0])
		}
		number, parseErr := parseUint(row[1], 32, "part number")
		if parseErr != nil {
			return MetadataManifest{}, fmt.Errorf("metadata manifest record %d: %w", record, parseErr)
		}
		count, parseErr := parseUint(row[2], 32, "part count")
		if parseErr != nil {
			return MetadataManifest{}, fmt.Errorf("metadata manifest record %d: %w", record, parseErr)
		}
		size, parseErr := parseUint(row[7], 64, "part size")
		if parseErr != nil {
			return MetadataManifest{}, fmt.Errorf("metadata manifest record %d: %w", record, parseErr)
		}
		manifest.Parts = append(manifest.Parts, ManifestPart{Number: uint32(number), Count: uint32(count), ObjectID: row[3], Hash: row[4], SHA256: row[5], MD5: row[6], Size: size})
	}
	if err := manifest.validate(); err != nil {
		return MetadataManifest{}, fmt.Errorf("metadata manifest: %w", err)
	}
	return manifest, nil
}

func (manifest MetadataManifest) validate() error {
	if !uuidPattern.MatchString(manifest.RepositoryUUID) {
		return fmt.Errorf("invalid repository UUID %q", manifest.RepositoryUUID)
	}
	if !commitPattern.MatchString(manifest.TipCommit) {
		return fmt.Errorf("invalid tip commit %q", manifest.TipCommit)
	}
	switch manifest.Kind {
	case BundleFull:
		if manifest.Sequence != 0 || manifest.BaseCommit != "-" {
			return fmt.Errorf("full bundle must be the sequence-zero genesis bundle with base commit -")
		}
	case BundleIncremental:
		if manifest.Sequence == 0 || !commitPattern.MatchString(manifest.BaseCommit) || manifest.BaseCommit == manifest.TipCommit {
			return fmt.Errorf("incremental bundle has invalid sequence or base commit")
		}
	default:
		return fmt.Errorf("unknown bundle kind %q", manifest.Kind)
	}
	if !blake2bPattern.MatchString(manifest.BundleHash) {
		return fmt.Errorf("invalid bundle BLAKE2b %q", manifest.BundleHash)
	}
	if len(manifest.Parts) == 0 || len(manifest.Parts) > MaximumMetadataManifestParts {
		return fmt.Errorf("metadata bundle has an invalid part count")
	}
	if manifest.BundleSize == 0 {
		return fmt.Errorf("encrypted metadata bundle is empty")
	}
	var total uint64
	for index, part := range manifest.Parts {
		if part.Number != uint32(index) || part.Count != uint32(len(manifest.Parts)) {
			return fmt.Errorf("metadata bundle parts are not contiguous or have inconsistent counts")
		}
		if part.Size == 0 {
			return fmt.Errorf("metadata bundle part %d is empty", index)
		}
		if !objectIDPattern.MatchString(part.ObjectID) || !blake2bPattern.MatchString(part.Hash) || !sha256Pattern.MatchString(part.SHA256) || !md5Pattern.MatchString(part.MD5) {
			return fmt.Errorf("metadata bundle part %d has invalid identity or checksum", index)
		}
		if ^uint64(0)-total < part.Size {
			return fmt.Errorf("metadata bundle part sizes overflow")
		}
		total += part.Size
	}
	if total != manifest.BundleSize {
		return fmt.Errorf("metadata bundle size %d disagrees with part total %d", manifest.BundleSize, total)
	}
	return nil
}

func MetadataPartKey(part ManifestPart) (string, error) {
	if !blake2bPattern.MatchString(part.Hash) || !objectIDPattern.MatchString(part.ObjectID) {
		return "", fmt.Errorf("invalid metadata part identity")
	}
	return "metadata/parts/" + part.Hash + "/" + part.ObjectID, nil
}

func MetadataManifestKey(tipCommit, manifestHash, objectID string) (string, error) {
	if !commitPattern.MatchString(tipCommit) || !blake2bPattern.MatchString(manifestHash) || !objectIDPattern.MatchString(objectID) {
		return "", fmt.Errorf("invalid metadata manifest identity")
	}
	return "metadata/manifests/" + tipCommit + "/" + manifestHash + "/" + objectID, nil
}
