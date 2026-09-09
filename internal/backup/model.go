package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"backup/internal/filesystem"
	"backup/internal/format"
	"backup/internal/localconfig"
	"backup/internal/objectstore"

	"golang.org/x/sys/unix"
)

type ClientFactory func(context.Context, localconfig.Mirror) (*objectstore.Client, error)

const (
	stateVersion            = 4
	transactionFilename     = "transaction.json"
	ledgerFilename          = "completion-ledger.json"
	validatedAncestorFile   = "validated-ancestor.json"
	defaultPackTarget       = uint64(100 << 20)
	defaultPartSize         = uint64(1 << 30)
	defaultMetadataPartSize = uint64(64 << 20)
	defaultSpaceReserve     = uint64(1 << 30)
	metadataRepositoryName  = ".backup"
	operationalStateDirName = ".backup-state"
	transactionFilesDirName = "transaction-files"
	restoreTemporaryPrefix  = "backup-restore-"
)

type Options struct {
	Root              string
	ConfigPath        string
	PackTarget        uint64
	PartSize          uint64
	MetadataPartSize  uint64
	SpoolDirectory    string
	SpaceReserveBytes uint64
	ClientFactory     ClientFactory
	Stdout            io.Writer
	Stderr            io.Writer
	Now               func() time.Time
	failurePoint      func(string) error
}

func (options Options) normalized() (Options, error) {
	if options.Root == "" {
		return Options{}, fmt.Errorf("backup root is required")
	}
	absolute, err := filepath.Abs(options.Root)
	if err != nil {
		return Options{}, fmt.Errorf("resolve backup root: %w", err)
	}
	options.Root = absolute
	if options.ConfigPath == "" {
		options.ConfigPath = filepath.Join(absolute, ".backup-config")
	}
	if options.PackTarget == 0 {
		options.PackTarget = defaultPackTarget
	}
	if options.PartSize == 0 {
		options.PartSize = defaultPartSize
	}
	if options.MetadataPartSize == 0 {
		options.MetadataPartSize = defaultMetadataPartSize
	}
	if options.SpaceReserveBytes == 0 {
		options.SpaceReserveBytes = defaultSpaceReserve
	}
	if options.SpoolDirectory != "" {
		spool, err := filepath.Abs(options.SpoolDirectory)
		if err != nil {
			return Options{}, fmt.Errorf("resolve plaintext spool directory: %w", err)
		}
		options.SpoolDirectory = spool
	}
	if options.PackTarget == 0 || options.PartSize == 0 || options.MetadataPartSize == 0 || options.PartSize > uint64(^uint64(0)>>1) || options.MetadataPartSize > uint64(^uint64(0)>>1) {
		return Options{}, fmt.Errorf("pack and part sizes must be positive and representable")
	}
	if options.Stdout == nil {
		options.Stdout = io.Discard
	}
	if options.Stderr == nil {
		options.Stderr = io.Discard
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return options, nil
}

func (options Options) repositoryPath() string {
	return filepath.Join(options.Root, metadataRepositoryName)
}

func (options Options) statePath() string {
	return filepath.Join(options.repositoryPath(), operationalStateDirName)
}

func (options Options) transactionFilesPath() string {
	return filepath.Join(options.statePath(), transactionFilesDirName)
}

type InitResult struct {
	RepositoryUUID string
}

type SnapshotResult struct {
	CommitID        string
	CompleteMirrors []string
	LaggingMirrors  []string
	NoChanges       bool
}

type AddResult struct {
	BaseCommit       string
	Entries          int
	UniqueNewObjects int
	NewPacks         int
	NoChanges        bool
	Scan             filesystem.Result
}

type RestoreRequest struct {
	Pattern         string
	Revision        string
	CatalogRevision string
	TargetRoot      string
	DryRun          bool
	Overwrite       bool
	Report          func(RestoreEvent) error
}

type RestoreEventKind string

const (
	RestoreResolved  RestoreEventKind = "resolved"
	RestorePlanned   RestoreEventKind = "plan"
	RestorePublished RestoreEventKind = "published"
	RestoreRemaining RestoreEventKind = "remaining"
)

type RestoreEvent struct {
	Kind           RestoreEventKind
	SnapshotCommit string
	CatalogCommit  string
	Path           string
	FilesystemKind string
	Status         string
}

type RestoreResult struct {
	SnapshotCommit string
	CatalogCommit  string
	Planned        uint64
	Published      uint64
	Remaining      uint64
}

type MirrorVerification struct {
	Name     string
	Complete bool
	Error    string
}

type VerifyResult struct {
	CommitID string
	Passed   int
	Minimum  int
	Mirrors  []MirrorVerification
}

type RecoverRequest struct {
	Mirror      string
	Tip         string
	Destination string
	ListOnly    bool
	Report      func(RecoverEvent) error
}

type RecoverEvent struct {
	AvailableTip string
}

type RecoverResult struct {
	Available    uint64
	RecoveredTip string
	Destination  string
}

type SyncResult struct {
	Source         string
	Destination    string
	CommitID       string
	DataCopied     int
	MetadataCopied int
}

type RepairResult struct {
	CommitID        string
	PackHash        string
	PartNumber      uint32
	OldObjectID     string
	NewObjectID     string
	CompleteMirrors []string
}

type MetadataRepairResult struct {
	TipCommit        string
	ManifestHash     string
	ManifestObjectID string
	Parts            int
}

type DiffKind string

const (
	DiffAddition DiffKind = "addition"
	DiffDeletion DiffKind = "deletion"
	DiffChange   DiffKind = "change"
)

type Diff struct {
	Kind DiffKind
	Old  *format.IndexEntry
	New  *format.IndexEntry
}

type stagedDataPart struct {
	Entry        format.PackEntry `json:"entry"`
	RelativePath string           `json:"relative_path"`
}

type stagedMetadata struct {
	Manifest             format.MetadataManifest `json:"manifest"`
	ManifestHash         string                  `json:"manifest_hash"`
	ManifestObjectID     string                  `json:"manifest_object_id"`
	ManifestRelativePath string                  `json:"manifest_relative_path"`
	PartsDirectory       string                  `json:"parts_directory"`
}

type mirrorProgress struct {
	DataPartCursor     uint64 `json:"data_part_cursor"`
	MetadataPartCursor uint32 `json:"metadata_part_cursor"`
	MetadataManifest   bool   `json:"metadata_manifest"`
	DataComplete       bool   `json:"data_complete"`
	RevisionComplete   bool   `json:"revision_complete"`
}

type stagedFileRef struct {
	RelativePath string `json:"relative_path"`
	BLAKE2b      string `json:"blake2b"`
	Size         uint64 `json:"size"`
}

type stagedPlan struct {
	IndexFile   stagedFileRef            `json:"index_file"`
	ConfigFiles map[string]stagedFileRef `json:"config_files"`
	Entries     int                      `json:"entries"`
	AllowEmpty  bool                     `json:"allow_empty"`
}

type captureProgress struct {
	NextPlan       int             `json:"next_plan"`
	SegmentCount   uint64          `json:"segment_count"`
	SegmentHash    string          `json:"segment_hash"`
	Entries        uint64          `json:"entries"`
	Warnings       uint64          `json:"warnings"`
	WarningsShown  uint64          `json:"warnings_shown"`
	WarningSummary bool            `json:"warning_summary"`
	Mirrors        map[string]bool `json:"mirrors"`
}

type transaction struct {
	Version         int                        `json:"version"`
	Incident        uint64                     `json:"incident"`
	Kind            string                     `json:"kind"`
	BaseCommit      string                     `json:"base_commit"`
	Plan            *stagedPlan                `json:"plan,omitempty"`
	Capture         *captureProgress           `json:"capture,omitempty"`
	CandidateFiles  map[string]stagedFileRef   `json:"candidate_files,omitempty"`
	CandidateHashes map[string]string          `json:"candidate_hashes"`
	DataPartsFile   stagedFileRef              `json:"data_parts_file,omitempty"`
	DataPartCount   uint64                     `json:"-"`
	LocalCommit     string                     `json:"local_commit"`
	LocalAccepted   bool                       `json:"local_accepted"`
	Metadata        *stagedMetadata            `json:"metadata,omitempty"`
	PushAttempted   bool                       `json:"push_attempted"`
	PushConfirmed   bool                       `json:"push_confirmed"`
	Resetting       bool                       `json:"resetting"`
	Mirrors         map[string]*mirrorProgress `json:"mirrors"`
	CreatedUnixNano int64                      `json:"created_unix_nano"`
}

func newTransaction(kind, base string, now time.Time) transaction {
	return transaction{
		Version: stateVersion, Kind: kind, BaseCommit: base,
		Mirrors: make(map[string]*mirrorProgress), CreatedUnixNano: now.UnixNano(),
	}
}

func (txn *transaction) progress(name string) *mirrorProgress {
	if txn.Mirrors == nil {
		txn.Mirrors = make(map[string]*mirrorProgress)
	}
	progress := txn.Mirrors[name]
	if progress == nil {
		progress = &mirrorProgress{}
		txn.Mirrors[name] = progress
	}
	return progress
}

type completionLedger struct {
	Version        int               `json:"version"`
	RepositoryUUID string            `json:"repository_uuid"`
	Mirrors        map[string]string `json:"mirrors"`
	Incident       uint64            `json:"incident"`
	Quarantined    map[string]bool   `json:"quarantined"`
	ForwardRepair  string            `json:"forward_repair"`
}

func newCompletionLedger(repositoryUUID string) completionLedger {
	return completionLedger{Version: stateVersion, RepositoryUUID: repositoryUUID, Mirrors: make(map[string]string), Quarantined: make(map[string]bool)}
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open private directory without following symlinks: %w", err)
	}
	directory := os.NewFile(uintptr(fd), path)
	defer func() { _ = directory.Close() }()
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
