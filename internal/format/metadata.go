package format

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	KindFile    = "file"
	KindSymlink = "symlink"

	MirrorBackupServer = "backup-server"
	MirrorAWSS3        = "aws-s3"
	MirrorCloudflareR2 = "cloudflare-r2"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	namePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	regionPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	objectIDPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	blake2bPattern     = regexp.MustCompile(`^[0-9a-f]{128}$`)
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	md5Pattern         = regexp.MustCompile(`^[0-9a-f]{32}$`)
	commitPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	publicKeyPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fingerprintPattern = regexp.MustCompile(`^v1:blake2b-512:[0-9a-f]{128}$`)
)

type RepositoryFormat struct {
	ChecksumAlgorithms           string
	CompressionAlgorithm         string
	ContentHashAlgorithm         string
	EncryptionAlgorithm          string
	FormatVersion                string
	GitObjectFormat              string
	PackFormatVersion            string
	PackHashAlgorithm            string
	RecoveryRecipientFingerprint string
	RepositoryUUID               string
	TarAlgorithm                 string
}

func NewRepositoryFormat(repositoryUUID, recoveryFingerprint string) RepositoryFormat {
	return RepositoryFormat{
		ChecksumAlgorithms:           "blake2b-512,sha256,md5",
		CompressionAlgorithm:         "zstd",
		ContentHashAlgorithm:         "blake2b-512",
		EncryptionAlgorithm:          "go-libsodium-recipient-stream-v1",
		FormatVersion:                "1",
		GitObjectFormat:              "sha256",
		PackFormatVersion:            "1",
		PackHashAlgorithm:            "blake2b-512",
		RecoveryRecipientFingerprint: recoveryFingerprint,
		RepositoryUUID:               repositoryUUID,
		TarAlgorithm:                 "posix-pax-go-archive-tar-v1",
	}
}

func (format RepositoryFormat) rows() [][]string {
	return [][]string{
		{"checksum-algorithms", format.ChecksumAlgorithms},
		{"compression-algorithm", format.CompressionAlgorithm},
		{"content-hash-algorithm", format.ContentHashAlgorithm},
		{"encryption-algorithm", format.EncryptionAlgorithm},
		{"format-version", format.FormatVersion},
		{"git-object-format", format.GitObjectFormat},
		{"pack-format-version", format.PackFormatVersion},
		{"pack-hash-algorithm", format.PackHashAlgorithm},
		{"recovery-recipient-fingerprint", format.RecoveryRecipientFingerprint},
		{"repository-uuid", format.RepositoryUUID},
		{"tar-algorithm", format.TarAlgorithm},
	}
}

func (format RepositoryFormat) MarshalText() ([]byte, error) {
	if err := format.validate(); err != nil {
		return nil, err
	}
	return marshalRows(format.rows())
}

func ParseRepositoryFormat(reader io.Reader, limits Limits) (RepositoryFormat, error) {
	rows, err := readRows(reader, limits)
	if err != nil {
		return RepositoryFormat{}, fmt.Errorf("FORMAT: %w", err)
	}
	expected := NewRepositoryFormat("00000000-0000-4000-8000-000000000000", "v1:blake2b-512:"+strings.Repeat("0", 128)).rows()
	if len(rows) != len(expected) {
		return RepositoryFormat{}, fmt.Errorf("FORMAT has %d keys, expected %d", len(rows), len(expected))
	}
	values := make(map[string]string, len(rows))
	for index, row := range rows {
		if err := requireFieldCount(row, 2, index+1); err != nil {
			return RepositoryFormat{}, fmt.Errorf("FORMAT: %w", err)
		}
		if row[0] != expected[index][0] {
			return RepositoryFormat{}, fmt.Errorf("FORMAT key %d is %q, expected %q", index+1, row[0], expected[index][0])
		}
		values[row[0]] = row[1]
	}
	format := RepositoryFormat{
		ChecksumAlgorithms:           values["checksum-algorithms"],
		CompressionAlgorithm:         values["compression-algorithm"],
		ContentHashAlgorithm:         values["content-hash-algorithm"],
		EncryptionAlgorithm:          values["encryption-algorithm"],
		FormatVersion:                values["format-version"],
		GitObjectFormat:              values["git-object-format"],
		PackFormatVersion:            values["pack-format-version"],
		PackHashAlgorithm:            values["pack-hash-algorithm"],
		RecoveryRecipientFingerprint: values["recovery-recipient-fingerprint"],
		RepositoryUUID:               values["repository-uuid"],
		TarAlgorithm:                 values["tar-algorithm"],
	}
	if err := format.validate(); err != nil {
		return RepositoryFormat{}, fmt.Errorf("FORMAT: %w", err)
	}
	return format, nil
}

func (format RepositoryFormat) validate() error {
	fixed := map[string]string{
		"checksum-algorithms":    format.ChecksumAlgorithms,
		"compression-algorithm":  format.CompressionAlgorithm,
		"content-hash-algorithm": format.ContentHashAlgorithm,
		"encryption-algorithm":   format.EncryptionAlgorithm,
		"format-version":         format.FormatVersion,
		"git-object-format":      format.GitObjectFormat,
		"pack-format-version":    format.PackFormatVersion,
		"pack-hash-algorithm":    format.PackHashAlgorithm,
		"tar-algorithm":          format.TarAlgorithm,
	}
	expected := map[string]string{
		"checksum-algorithms":    "blake2b-512,sha256,md5",
		"compression-algorithm":  "zstd",
		"content-hash-algorithm": "blake2b-512",
		"encryption-algorithm":   "go-libsodium-recipient-stream-v1",
		"format-version":         "1",
		"git-object-format":      "sha256",
		"pack-format-version":    "1",
		"pack-hash-algorithm":    "blake2b-512",
		"tar-algorithm":          "posix-pax-go-archive-tar-v1",
	}
	for key, value := range fixed {
		if value != expected[key] {
			return fmt.Errorf("unsupported %s %q", key, value)
		}
	}
	if !uuidPattern.MatchString(format.RepositoryUUID) {
		return fmt.Errorf("invalid repository UUID %q", format.RepositoryUUID)
	}
	if !fingerprintPattern.MatchString(format.RecoveryRecipientFingerprint) {
		return fmt.Errorf("invalid recovery recipient fingerprint %q", format.RecoveryRecipientFingerprint)
	}
	return nil
}

type IndexEntry struct {
	Path    string
	Kind    string
	Ref     string
	Size    uint64
	Mode    uint32
	MtimeNS int64
}

func (entry IndexEntry) row() ([]string, error) {
	if err := validateIndexEntry(entry); err != nil {
		return nil, err
	}
	if entry.Kind == KindSymlink {
		return []string{entry.Path, entry.Kind, entry.Ref, "0", "-", "-"}, nil
	}
	return []string{entry.Path, entry.Kind, entry.Ref, uintText(entry.Size), fmt.Sprintf("%04o", entry.Mode), intText(entry.MtimeNS)}, nil
}

func MarshalIndex(entries []IndexEntry) ([]byte, error) {
	rows := make([][]string, len(entries))
	for index, entry := range entries {
		row, err := entry.row()
		if err != nil {
			return nil, fmt.Errorf("index entry %d: %w", index+1, err)
		}
		rows[index] = row
	}
	if err := validateIndexOrder(entries); err != nil {
		return nil, err
	}
	return marshalRows(rows)
}

func ParseIndex(reader io.Reader, limits Limits) ([]IndexEntry, error) {
	entries := make([]IndexEntry, 0)
	if err := WalkIndex(reader, limits, func(entry IndexEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := validateIndexOrder(entries); err != nil {
		return nil, fmt.Errorf("index.tsv: %w", err)
	}
	return entries, nil
}

func validateIndexEntry(entry IndexEntry) error {
	if err := ValidatePath(entry.Path); err != nil {
		return fmt.Errorf("invalid path %q: %w", entry.Path, err)
	}
	switch entry.Kind {
	case KindFile:
		if !strings.HasPrefix(entry.Ref, "blake2b:") || !blake2bPattern.MatchString(strings.TrimPrefix(entry.Ref, "blake2b:")) {
			return fmt.Errorf("invalid file reference %q", entry.Ref)
		}
		if entry.Mode > 0o777 {
			return fmt.Errorf("invalid file mode %04o", entry.Mode)
		}
	case KindSymlink:
		if entry.Size != 0 || entry.Mode != 0 || entry.MtimeNS != 0 {
			return fmt.Errorf("symlink has file metadata")
		}
		if !strings.HasPrefix(entry.Ref, "target:") {
			return fmt.Errorf("invalid symlink reference %q", entry.Ref)
		}
		if err := ValidateSymlinkTarget(strings.TrimPrefix(entry.Ref, "target:")); err != nil {
			return fmt.Errorf("invalid symlink target: %w", err)
		}
	default:
		return fmt.Errorf("unknown kind %q", entry.Kind)
	}
	return nil
}

func validateIndexOrder(entries []IndexEntry) error {
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if index > 0 {
			previous := entries[index-1].Path
			if previous >= entry.Path {
				return fmt.Errorf("paths are not sorted uniquely at %q and %q", previous, entry.Path)
			}
		}
		parent := entry.Path
		for {
			slash := strings.LastIndexByte(parent, '/')
			if slash <= 1 {
				break
			}
			parent = parent[:slash]
			if _, exists := seen[parent]; exists {
				return fmt.Errorf("indexed leaf %q is an ancestor of %q", parent, entry.Path)
			}
		}
		seen[entry.Path] = struct{}{}
	}
	return nil
}

func ValidateSymlinkTarget(value string) error {
	if value == "./" {
		return nil
	}
	return ValidatePath(value)
}

func ValidatePath(value string) error {
	if !strings.HasPrefix(value, "./") || len(value) <= 2 {
		return fmt.Errorf("path must begin with ./ and name a leaf")
	}
	if err := validateRawField(value); err != nil {
		return err
	}
	relative := strings.TrimPrefix(value, "./")
	if strings.HasPrefix(relative, "/") || relative == "." || relative == ".." {
		return fmt.Errorf("absolute or dot path")
	}
	if path.Clean(relative) != relative {
		return fmt.Errorf("noncanonical path")
	}
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid path component")
		}
	}
	return nil
}

type ObjectEntry struct {
	PlaintextHash string
	PlaintextSize uint64
	PackHash      string
}

func MarshalObjects(entries []ObjectEntry) ([]byte, error) {
	rows := make([][]string, len(entries))
	for index, entry := range entries {
		if err := validateObjectEntry(entry); err != nil {
			return nil, fmt.Errorf("objects entry %d: %w", index+1, err)
		}
		if index > 0 && entries[index-1].PlaintextHash >= entry.PlaintextHash {
			return nil, fmt.Errorf("objects are not sorted uniquely")
		}
		rows[index] = []string{entry.PlaintextHash, uintText(entry.PlaintextSize), entry.PackHash}
	}
	return marshalRows(rows)
}

func ParseObjects(reader io.Reader, limits Limits) ([]ObjectEntry, error) {
	entries := make([]ObjectEntry, 0)
	if err := WalkObjects(reader, limits, func(entry ObjectEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func validateObjectEntry(entry ObjectEntry) error {
	if !blake2bPattern.MatchString(entry.PlaintextHash) {
		return fmt.Errorf("invalid plaintext BLAKE2b %q", entry.PlaintextHash)
	}
	if !blake2bPattern.MatchString(entry.PackHash) {
		return fmt.Errorf("invalid pack BLAKE2b %q", entry.PackHash)
	}
	return nil
}

type PackEntry struct {
	PackHash   string
	PartNumber uint32
	PartCount  uint32
	PartHash   string
	PartSHA256 string
	PartMD5    string
	PartSize   uint64
	ObjectID   string
}

func (entry PackEntry) row() ([]string, error) {
	if err := validatePackEntry(entry); err != nil {
		return nil, err
	}
	return []string{entry.PackHash, uintText(uint64(entry.PartNumber)), uintText(uint64(entry.PartCount)), entry.PartHash, entry.PartSHA256, entry.PartMD5, uintText(entry.PartSize), entry.ObjectID}, nil
}

func MarshalPacks(entries []PackEntry) ([]byte, error) {
	if err := validatePackSequence(entries); err != nil {
		return nil, err
	}
	rows := make([][]string, len(entries))
	for index, entry := range entries {
		row, err := entry.row()
		if err != nil {
			return nil, fmt.Errorf("packs entry %d: %w", index+1, err)
		}
		rows[index] = row
	}
	return marshalRows(rows)
}

func ParsePacks(reader io.Reader, limits Limits) ([]PackEntry, error) {
	entries := make([]PackEntry, 0)
	if err := WalkPacks(reader, limits, func(entry PackEntry) error {
		entries = append(entries, entry)
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func validatePackEntry(entry PackEntry) error {
	if !blake2bPattern.MatchString(entry.PackHash) || !blake2bPattern.MatchString(entry.PartHash) {
		return fmt.Errorf("invalid BLAKE2b hash")
	}
	if !sha256Pattern.MatchString(entry.PartSHA256) || !md5Pattern.MatchString(entry.PartMD5) {
		return fmt.Errorf("invalid provider checksum")
	}
	if entry.PartCount == 0 || entry.PartNumber >= entry.PartCount {
		return fmt.Errorf("invalid part number/count %d/%d", entry.PartNumber, entry.PartCount)
	}
	if entry.PartSize == 0 {
		return fmt.Errorf("encrypted pack part is empty")
	}
	if !objectIDPattern.MatchString(entry.ObjectID) {
		return fmt.Errorf("invalid object ID %q", entry.ObjectID)
	}
	return nil
}

func validatePackSequence(entries []PackEntry) error {
	for index, entry := range entries {
		if err := validatePackEntry(entry); err != nil {
			return fmt.Errorf("entry %d: %w", index+1, err)
		}
		if index == 0 || entries[index-1].PackHash != entry.PackHash {
			if index > 0 && entries[index-1].PackHash >= entry.PackHash {
				return fmt.Errorf("packs are not sorted uniquely")
			}
			if entry.PartNumber != 0 {
				return fmt.Errorf("pack %s starts at part %d", entry.PackHash, entry.PartNumber)
			}
		} else {
			previous := entries[index-1]
			if entry.PartCount != previous.PartCount || entry.PartNumber != previous.PartNumber+1 {
				return fmt.Errorf("pack %s has inconsistent or noncontiguous parts", entry.PackHash)
			}
		}
		lastForPack := index == len(entries)-1 || entries[index+1].PackHash != entry.PackHash
		if lastForPack && entry.PartNumber+1 != entry.PartCount {
			return fmt.Errorf("pack %s is missing terminal parts", entry.PackHash)
		}
	}
	return nil
}

type Mirror struct {
	Name     string
	Kind     string
	S3URL    string
	Endpoint string
	Region   string
}

func MarshalMirrors(mirrors []Mirror) ([]byte, error) {
	rows := make([][]string, len(mirrors))
	for index, mirror := range mirrors {
		if err := validateMirror(mirror); err != nil {
			return nil, fmt.Errorf("mirror %d: %w", index+1, err)
		}
		if index > 0 && mirrors[index-1].Name >= mirror.Name {
			return nil, fmt.Errorf("mirror names are not sorted uniquely")
		}
		rows[index] = []string{mirror.Name, mirror.Kind, mirror.S3URL, mirror.Endpoint, mirror.Region}
	}
	return marshalRows(rows)
}

func ParseMirrors(reader io.Reader, limits Limits) ([]Mirror, error) {
	rows, err := readRows(reader, limits)
	if err != nil {
		return nil, fmt.Errorf("mirrors.tsv: %w", err)
	}
	mirrors := make([]Mirror, 0, len(rows))
	for rowIndex, row := range rows {
		if err := requireFieldCount(row, 5, rowIndex+1); err != nil {
			return nil, fmt.Errorf("mirrors.tsv: %w", err)
		}
		mirror := Mirror{Name: row[0], Kind: row[1], S3URL: row[2], Endpoint: row[3], Region: row[4]}
		if err := validateMirror(mirror); err != nil {
			return nil, fmt.Errorf("mirrors.tsv record %d: %w", rowIndex+1, err)
		}
		if len(mirrors) > 0 && mirrors[len(mirrors)-1].Name >= mirror.Name {
			return nil, fmt.Errorf("mirrors.tsv is not sorted uniquely at record %d", rowIndex+1)
		}
		mirrors = append(mirrors, mirror)
	}
	return mirrors, nil
}

func validateMirror(mirror Mirror) error {
	if !namePattern.MatchString(mirror.Name) {
		return fmt.Errorf("invalid name %q", mirror.Name)
	}
	switch mirror.Kind {
	case MirrorBackupServer, MirrorAWSS3, MirrorCloudflareR2:
	default:
		return fmt.Errorf("unknown kind %q", mirror.Kind)
	}
	parsed, err := url.Parse(mirror.S3URL)
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid S3 URL %q", mirror.S3URL)
	}
	if parsed.Path != "" && (strings.HasSuffix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path) {
		return fmt.Errorf("noncanonical S3 URL %q", mirror.S3URL)
	}
	if mirror.Endpoint != "-" {
		endpoint, parseErr := url.Parse(mirror.Endpoint)
		if parseErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return fmt.Errorf("invalid HTTPS endpoint %q", mirror.Endpoint)
		}
	}
	if mirror.Kind == MirrorAWSS3 && mirror.Endpoint != "-" {
		return fmt.Errorf("AWS S3 requires the provider-default endpoint")
	}
	if !regionPattern.MatchString(mirror.Region) {
		return fmt.Errorf("invalid region %q", mirror.Region)
	}
	return nil
}

func ValidateCatalogs(index []IndexEntry, objects []ObjectEntry, packs []PackEntry) error {
	if err := validateIndexOrder(index); err != nil {
		return err
	}
	if err := validatePackSequence(packs); err != nil {
		return err
	}
	objectByHash := make(map[string]ObjectEntry, len(objects))
	for position, object := range objects {
		if err := validateObjectEntry(object); err != nil {
			return fmt.Errorf("object %d: %w", position+1, err)
		}
		if position > 0 && objects[position-1].PlaintextHash >= object.PlaintextHash {
			return fmt.Errorf("objects are not sorted uniquely")
		}
		objectByHash[object.PlaintextHash] = object
	}
	packSet := make(map[string]struct{})
	for _, pack := range packs {
		packSet[pack.PackHash] = struct{}{}
	}
	for _, object := range objects {
		if _, ok := packSet[object.PackHash]; !ok {
			return fmt.Errorf("object %s references missing pack %s", object.PlaintextHash, object.PackHash)
		}
	}
	for _, entry := range index {
		if err := validateIndexEntry(entry); err != nil {
			return err
		}
		if entry.Kind != KindFile {
			continue
		}
		hash := strings.TrimPrefix(entry.Ref, "blake2b:")
		object, ok := objectByHash[hash]
		if !ok {
			return fmt.Errorf("file %q references missing object %s", entry.Path, hash)
		}
		if object.PlaintextSize != entry.Size {
			return fmt.Errorf("file %q size %d disagrees with object size %d", entry.Path, entry.Size, object.PlaintextSize)
		}
	}
	return nil
}

func RecoveryFingerprint(publicKey []byte) string {
	digest := blake2b.Sum512(publicKey)
	return "v1:blake2b-512:" + hex.EncodeToString(digest[:])
}

func ObjectKey(partHash, objectID string) (string, error) {
	if !blake2bPattern.MatchString(partHash) || !objectIDPattern.MatchString(objectID) {
		return "", fmt.Errorf("invalid object hash or ID")
	}
	return "objects/" + partHash + "/" + objectID, nil
}

func SortIndex(entries []IndexEntry) {
	sort.Slice(entries, func(left, right int) bool { return entries[left].Path < entries[right].Path })
}

func SortObjects(entries []ObjectEntry) {
	sort.Slice(entries, func(left, right int) bool { return entries[left].PlaintextHash < entries[right].PlaintextHash })
}

func SortPacks(entries []PackEntry) {
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].PackHash != entries[right].PackHash {
			return entries[left].PackHash < entries[right].PackHash
		}
		return entries[left].PartNumber < entries[right].PartNumber
	})
}
