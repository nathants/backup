# Backup design and operations

## Status

This repository is a clean-break Go rewrite. There is no legacy backup data to preserve or migrate: its first production backup starts a new format from scratch.

This document is the authoritative design agreed with Admin.

Before changing a settled design choice with a material tradeoff, stop and discuss it with Admin. Unambiguous correctness, durability, safety, and cleanup work does not need to be reopened.

## Priorities

In order:

1. Backed-up data and metadata remain recoverable.
2. A ransomware-compromised backup client cannot overwrite or delete existing remote data.
3. Every reported successful revision is complete on at least one individual mirror.
4. Restore never writes unverified or partial content and never escapes its target root.
5. The design is simple, understandable, auditable, and amenable to raw-file archaeology.
6. Operations are resumable and idempotent after crashes, lost responses, and partial remote failures.

Prefer boring files and explicit invariants over clever abstractions. Complexity must pay for a concrete and substantial benefit.

## Threat model

Protect against:

- ransomware or other compromise of a backup client and its ordinary upload credentials;
- accidental client bugs, retries, crashes, and partial network failures;
- object loss, absence, or bit corruption on one mirror;
- loss of the primary metadata Git service when at least one self-contained object mirror survives;
- unsafe paths or metadata received from an untrusted/corrupt Git remote;
- a lagging or temporarily unavailable mirror.

A compromised backup-server host/root account is out of scope; all bets are off at that boundary. Provider/account administrators are also outside the ordinary client-compromise boundary. A write credential can consume capacity by creating new valid objects; it must still be unable to mutate existing ones. Use dedicated storage, quotas/reserved free space, and external capacity monitoring.

## High-level architecture

One `backup` Go binary provides client and server subcommands.

Two logical stores exist:

1. **Metadata Git repository** at `$BACKUP_ROOT/.backup`:
   - one branch and fast-forward-only history;
   - Git SHA-256 object format from initialization;
   - encrypted remote hosting through `git-remote-aws` in production, while filesystem bare remotes may be used in tests and explicitly repinned temporary disaster-rescue reads;
   - plaintext, sorted, human-readable metadata in the local checkout;
   - Git history is the audit log; commit messages are diagnostic, never a database.

2. **One or more S3-compatible object mirrors**:
   - local production `backup server`, AWS S3, and Cloudflare R2 use the same narrow client protocol;
   - packs and self-contained metadata deltas are encrypted once and uploaded as identical immutable object bytes to each mirror;
   - mirrors may lag and later be caught up.

All three object backends use one ordinary credential per mirror for read, list, and immutable creation. The same profile serves backup, restore, verify, sync, and repair; overwrite, deletion, configuration changes, and credential/permission escalation remain forbidden. Provider/account administration stays separate and off backup clients. A stolen ordinary credential can read historical ciphertext and plaintext completion manifests, but cannot decrypt encrypted content without a recipient secret. Read access is part of the ordinary credential; separate upload-only/read-only roles are not required. A cloud read-only credential remains an optional deployment restriction for an audit/restore-only machine, not another configured role. The backup server exposes one read/list/create credential, not a role system.

Each repository and its prefixes across all mirrors have **one authoritative writable checkout and operational ledger**. This is an implicit single-writer convention, not multi-machine snapshot aggregation: backup commits, sync, data repair, and metadata repair all run through that owner. Other machines may read/audit, but their observations do not automatically update or pause the owner's local state; authoritative integrity audits must run through the owner. Multiple independent writable checkouts on one hostname are also outside this convention. There is no hostname binding, owner record, lease, distributed election, or runtime ownership enforcement. Keep local locking, administrative credential separation, history validation, and Git fast-forward/CAS defenses against accidental overlap.

A replacement machine may take over explicitly: retire/revoke the old writer, recover validated metadata, freshly verify the mirrors and rebuild the operational ledger, then enable the replacement writer. Ownership is not a permanent physical-machine identity.

## Build and trusted local configuration

Builds use the published GitHub dependency versions pinned in `go.mod`. Local replacements are temporary development overrides only while actively changing an unpublished shared dependency, and must be removed before committing its published dependency update.

Build `./backup` with either `make` (the default target) or:

```sh
make build
```

Go 1.27 or newer, Linux 5.8 or newer, Git 2.36 or newer with SHA-256 support, and libsodium are required. Every hardened Git invocation pins `core.fsync=objects,reference` and `core.fsyncMethod=fsync`, overriding repository and ambient settings. A bounded version preflight rejects unsupported/unrecognized Git before running repository commands and retains the checked executable path for the process. This hardens local crash resumability at the cost of storage-dependent metadata sync latency; it relies on Git and the filesystem/hardware honoring fsync, not custom journaling or a universal power-loss guarantee. Restore uses `utimensat` with `AT_EMPTY_PATH` to apply nanosecond timestamps through the verified file descriptor, never through a mutable temporary filename. Production metadata hosting uses `git-remote-aws`.

By default the client reads `$BACKUP_ROOT/.backup-config`, where `BACKUP_ROOT` defaults to `/`. The file must be a bounded regular file that is not group/other writable. Its raw tab/LF format is:

```text
git-remote	aws://metadata-bucket+dynamodb-table/repository
branch	main
mirror	local	backup-server	s3://backup-bucket/repository	https://backup.example:8443	us-east-1	backup-profile	/etc/backup/ca.pem
```

A mirror row is `mirror name kind s3_url endpoint region profile ca_file`, with fields separated by tabs. Use `-` for a provider-default endpoint, an absent credential profile, or system trust roots. Configure one standard AWS shared-credential profile per mirror. This is a hard cutover: the old nine-field dual-profile rows are rejected; use eight fields. Canonical metadata and encrypted object formats are unchanged. Local CA paths and credentials remain local; canonical `mirrors.tsv` contains only nonsecret topology. Before any network request, trusted configuration must pin and exactly match the selected canonical mirror's name, kind, bucket, prefix, endpoint, and region.

## Metadata files

All canonical metadata is versioned in Git. `FORMAT` is a small headerless `key<TAB>value<LF>` file with unique keys sorted by unsigned UTF-8 bytes. Each recognized schema version has an exact required key set that includes the schema version, repository UUID, Git object format, content/pack/checksum/compression/encryption/tar algorithms. FORMAT version 2 has no recovery-recipient field; the earlier test-only version 1 is rejected without migration. Every value is fixed at repository initialization and may never change; missing, duplicate, extra, or unsupported keys/versions fail closed.

Every canonical `.tsv` is raw, unquoted, headerless UTF-8: fields are separated by one tab, records by one LF, every nonempty file ends in LF, and an empty table is a zero-byte file. The schema lines shown below are documentation, not stored rows. No CSV quoting, escaping, BOM, CR, Unicode normalization, locale collation, or insignificant whitespace exists. Sort and compare canonical strings by unsigned UTF-8 bytes and encode decimal integers without a sign or leading zero except `0`; fields whose schemas allow signed values define that explicitly.

### `index.tsv`

The filesystem snapshot at that Git revision, sorted uniquely by path:

```text
path    kind    ref    size    mode    mtime_ns
```

- `path`: canonical root-relative path beginning `./`.
- `kind`: `file` or `symlink`.
- file `ref`: `blake2b:<128 lowercase hex>`.
- symlink `ref`: `target:<canonical ./ root-relative realpath>`; the backup root itself is represented exactly as `target:./`.
- `size`: plaintext bytes for a file; `0` for a symlink.
- `mode`: exactly four octal digits recording regular-file permission bits `0000` through `0777`; `-` for a symlink.
- `mtime_ns`: regular-file modification time as canonical signed decimal Unix nanoseconds within `int64` range (a leading `-` only when negative); `-` for a symlink. A source timestamp outside that representable range fails rather than wrapping. Apply it to the fully written destination temp file after chmod and before fsync/publication.

Paths with spaces are supported. NUL, tab, CR, and LF are rejected. Invalid/noncanonical paths fail the operation; nothing is silently omitted except explicitly supported skip cases.

### `objects.tsv`

The cumulative dedup catalog, sorted uniquely by plaintext hash:

```text
plaintext_blake2b    plaintext_size    pack_blake2b
```

Every plaintext hash appears once and its recorded size is permanent. Many hashes may reference one logical pack. Ordinary backup operations never remove or remap these rows.

### `packs.tsv`

The current physical catalog for encrypted pack parts, sorted by pack and part number:

```text
pack_blake2b    part_number    part_count    part_blake2b    part_sha256    part_md5    part_size    object_id
```

- `pack_blake2b` is the BLAKE2b-512 of the complete encrypted pack stream before splitting and is the stable logical pack identity.
- `part_number` is zero-based; rows for a pack are contiguous and ordered.
- `part_count` is repeated on each row and detects missing terminal rows cheaply.
- `part_blake2b` and `part_size` identify and bound one physical ciphertext part.
- `part_sha256` and `part_md5` are lowercase hashes of the same part, computed in the same streaming pass. They exist solely for provider-side checksum verification; never infer MD5 from an ETag unless that provider documents the exact single-PUT semantics used.
- `object_id` is 32 lowercase hex characters encoding a persisted 128-bit `crypto/rand` value chosen before upload. It permits immutable relocation of identical healthy bytes after corruption.
- The physical object key is derived, never stored redundantly:
  `objects/<part_blake2b>/<object_id>`.
- The hash component lets the server validate bytes against the requested key.

An explicit repair may replace the affected part's `object_id` in a new fast-forward Git commit while retaining its pack/part hashes and sizes. The previous mapping remains visible in Git history and the previous object is never removed.

### `ignore`

One exact Go regular expression per nonempty UTF-8/LF line, with no trimming, comments, CR, NUL, or implicit anchoring. Compile every expression before scanning and apply `MatchString` to each canonical `./` root-relative path; a matching directory is pruned with all descendants. Invalid expressions are fatal. It remains a simple tracked text file.

### `.publickeys`

The tracked list uses the shared go-libsodium key-chain model also used by git-remote-aws. Each nonempty line is one individual's public chain: 64 lowercase hex characters per generation, joined with `:`, oldest first. Recipient rows form an unordered set: no sorting is required or performed. Blank lines are ignored and a final LF is optional; spaces, tabs, CR, comments, and duplicate keys remain forbidden. Generations within a chain remain ordered. Serialization preserves recipient row order and emits one LF per nonempty row; tracked file bytes are preserved, not automatically normalized. There are at most 1,024 generations per chain and 65,536 keys in total, bounded to 4,259,840 raw input bytes including blank lines. A single key is a one-generation chain. Retained chains may only extend on the right; entire recipients may be added or removed, leaving at least one for publication. Chains are not signed and do not confer storage/Git write authorization.

Encrypt new objects to only the final generation of each recipient. Each encrypted object can be decrypted with any matching retained secret generation; other recipients' secrets are not required. Retain historical private generations for historical decryption. There is no permanent/offline recovery-recipient requirement or special decryption path. Losing all matching secrets loses the corresponding ciphertext; rotations and recipient removal cannot revoke already obtained ciphertext. Existing ciphertext is not automatically re-encrypted.

`init` creates this file empty; local preparation add/diff/reset permit emptiness, but commit rejects it before remote binding or publication. Read [Key management](docs/key-management.md) before generating/rotating keys or configuring secret sources. Keygen lives in git-remote-aws and manages only explicit personal public/private files; it never automatically updates repository recipient lists. Pass only personal files to keygen, not repository `.publickeys`. Shared parsing, native key-chain validation, generation, key selection, and encryption live in go-libsodium; recipient decryption uses only `Keyring.Decrypt`, with no single-secret compatibility wrapper. Both applications use exactly one nonempty `GIT_REMOTE_AWS_SECRETKEY`, `GIT_REMOTE_AWS_SECRETKEY_FILE`, or `GIT_REMOTE_AWS_SECRETKEY_CMD` source, loaded only for decryption and reused across objects. Secret files allow only owner read/write permission bits, with no execute or special bits. While an external secret command runs, the shared application loader connects SIGINT/SIGTERM to cancellation, terminates its process group on cancellation/output overflow, and gives inherited output pipes a 250ms post-exit drain limit. It hands a foreground terminal to the loader and restores it before returning, including on exec failure. Terminal-attached background command loading fails explicitly; use the foreground or a detached invocation. Signal handling is scoped to loading, not global interception of unrelated CLI operations. There is no overall pinentry deadline, SIGKILL cleanup guarantee, or escaped-job sandbox. Backup's former `BACKUP_SECRET_KEY` variables are removed.

### `mirrors.tsv`

Tracked nonsecret mirror topology:

```text
name    kind    s3_url    endpoint    region
```

Names are unique and rows are sorted by name. Once introduced, a name and its kind/bucket/prefix/endpoint/region identity are permanent in history; removing a mirror later is allowed, but rebinding or reusing its name is not—add a new name instead. `kind` is a closed backend identifier such as `backup-server`, `aws-s3`, or `cloudflare-r2`; unknown kinds fail closed. `s3_url` contains bucket and prefix; endpoint is `-` for the provider default. The permanent bucket/prefix is the repository's object-store namespace: repositories sharing a bucket require unique, non-overlapping prefixes, and credentials plus immutability controls must cover the intended exact prefix. `FORMAT` does not duplicate this routing identity. Secrets and local CA paths are never tracked.

Canonical topology is recovery/audit metadata, not authority to redirect live credentials; the trusted local pin above is the network authority. Clients never follow endpoint redirects, and TLS must authenticate the exact pinned/default-provider hostname through configured trust roots.

### Historical restore and repair rule

By default, read `index.tsv`, `objects.tsv`, and `packs.tsv` from the requested snapshot revision. This makes an ordinary historical restore reproducible and independent of later metadata.

A later immutable relocation can repair that historical restore explicitly:

```text
backup restore ... SNAPSHOT --catalog-revision CATALOG
```

Resolve and print both revisions once as exact commit IDs. `CATALOG` must be the same repository identity and a descendant of `SNAPSHOT`. Continue reading `index.tsv` and `objects.tsv` from `SNAPSHOT`; read `packs.tsv` from `CATALOG`. For every pack reachable from the snapshot's object rows, the alternate catalog must preserve pack identity, part count/order, ciphertext hashes, checksums, and sizes exactly; only `object_id` may differ through valid relocation commits. Later unrelated pack rows are harmless.

Try every eligible mirror using the chosen catalog mapping. If a required historical part is absent everywhere or fails its recorded part size/BLAKE2b, fail before publication and report whether validated HEAD offers a compatible relocation, but never switch catalogs silently. The operator may retry explicitly with HEAD or a known-good repair commit. If all part bytes match their recorded ciphertext hashes but decryption, decompression, tar, or plaintext verification fails, relocation cannot help because a valid relocation contains those same ciphertext bytes.

### Required metadata invariants

Validate before every material operation:

- exact field counts and valid UTF-8/control-character policy;
- inspect Git object type and declared blob size before reading; stream every parser with explicit per-record/field/count bounds, checked integer arithmetic, and no allocation chosen directly by untrusted lengths; use sorted merge validation rather than duplicating cumulative catalogs in memory where practical;
- canonical sorted order and uniqueness, with no file/symlink path that is an ancestor of another snapshot path;
- valid lowercase fixed-length hashes, sizes, permission bits, mtimes, kinds, and references;
- Git uses SHA-256 object format and `FORMAT` identity fields exactly match repository genesis;
- every accepted commit tree contains exactly the seven required root-level regular blobs (`FORMAT`, `index.tsv`, `objects.tsv`, `packs.tsv`, `ignore`, `.publickeys`, and `mirrors.tsv`) with mode `100644`; reject missing/extra paths, trees, symlinks, submodules, and executable modes;
- metadata history has exactly one genesis commit and one parent per later commit; validate every untrusted commit and allowed state transition from genesis or an already pinned validated ancestor before accepting the tip;
- every file ref has exactly one object mapping with the same plaintext size;
- every referenced pack has one contiguous, internally consistent part set;
- object keys, their embedded hashes, and explicit hashes agree;
- classify transitions from validated tree diffs, never commit messages: an ordinary transition may change `index.tsv`/mutable configuration and add new immutable `objects.tsv`/`packs.tsv` rows but cannot remove or alter prior catalog rows; a repair transition may change only one or more existing `packs.tsv.object_id` values with every other blob and logical field identical; reject mixed, destructive, or unclassifiable transitions;
- repository UUID agrees across `FORMAT` and metadata manifests, and trusted local mirror identities agree with canonical topology;
- no Git command error is inferred from matching words such as `fatal`; classify exact exit outcomes.

Inspect fetched Git objects with plumbing commands before exposing them to a worktree; never checkout an unvalidated remote tree. Invoke Git with a sanitized environment, disabled hooks and filters, literal path handling, and the fixed branch/remote configuration. Before materializing a fetched fast-forward, require a clean metadata worktree relative to the current local commit, including canonical file bytes/types/modes and absence of unrelated untracked paths. Refuse with the changed paths before recording materialization intent or moving the local branch; preserve local configuration edits and any existing add plan. Do not merge or discard edits automatically. An unchanged remote still permits the normal mutable-configuration edit/add workflow. After validation, materialize only the allowlisted blobs through controlled atomic file writes.

Validate every candidate file and all cross-file invariants before materialization. Write each file atomically with a unique temp file, fsync, rename, and containing-directory fsync. The Git commit is the atomic metadata revision boundary: interrupted pre-commit materialization is detected from durable staging and completed or rolled back before any later operation; a mixed working tree is never committed.

## Pack and object format

New plaintext files are deduplicated by BLAKE2b-512. Each unique new hash is stored once.

Logical pack pipeline:

```text
tar members captured in lexical add-plan path order and named by plaintext BLAKE2b
-> zstd
-> git-remote-aws-compatible libsodium recipient encryption
-> fixed-size ciphertext splitter
```

Properties:

- File-level deduplication remains the stable semantic.
- Tar is POSIX PAX written and read exclusively with Go's standard-library `archive/tar`; set `Header.Format = tar.FormatPAX` and do not add a third-party tar implementation. Members are `TypeReg` files named by the 128-character lowercase plaintext hash. Hash sorting is not a format invariant: commit processes the add-time path plan lexically and appends each newly deduplicated member as soon as its one-file spool is complete. Headers have fixed content-only fields: member size, mode `0600`, numeric UID/GID `0`, empty user/group/link names, `ModTime` at the Unix epoch, absent access/change times, nil caller-supplied PAX/xattr maps, and zero device numbers. The standard library consequently emits only the required `path` record and, for files too large for the base header, `size`; readers require those records to agree exactly and reject every other PAX record, duplicate/unexpected/non-regular member, inconsistent size, noncanonical end marker, or trailing decompressed data. Every expected member must appear exactly once, but readers do not require hash order.
- Each tar member is rehashed while being packed and again when restored/fully verified.
- Default logical pack target remains approximately 100 MiB; one file may exceed it.
- Encrypted output is split into ordinary objects of at most approximately 1 GiB by default. This supports arbitrarily large files without multipart S3 or file-chunk metadata.
- Each part uses a normal single `PutObject` with `If-None-Match: *` and supplies the full-object checksum headers supported by that backend: explicit SHA-256 plus MD5 for AWS S3 and `backup-server`, and explicit SHA-256 only for Cloudflare R2 because R2 rejects simultaneous SHA-256 and `Content-MD5` as multiple non-default checksums.
- BLAKE2b, SHA-256, MD5, and size are computed together while each ciphertext part is staged.
- Part bytes, key, size, and hash are fixed in durable staging before the first upload.
- Encryption is performed once; every mirror receives identical ciphertext parts.

Recovery remains mechanically simple:

```text
fetch ordered parts -> verify each BLAKE2b/size -> concatenate
-> git-remote-aws-compatible decrypt -> zstd decompress -> tar scan/extract
```

Use the existing public `backup` and `git-remote-aws` formats/projects as the recovery implementation dependency. A stock third-party decryptor is not required, but raw metadata and object relationships must remain understandable.

## Filesystem semantics

Supported:

- Linux;
- regular files;
- regular-file permission modes;
- file and directory symlinks using the original canonical-target behavior;
- duplicate paths/content through content deduplication;
- `BACKUP_ROOT=/` when the process already has required privileges;
- paths containing spaces;
- traversal across mounted filesystems by default, with every entered mount visibly reported.

Directory mount diagnostics compare Linux `statx(STATX_MNT_ID)` identities from opened descriptors, including same-device bind mounts; the backup root itself and ordinary subdirectories do not produce boundary events. Linux 5.8 supplies this capability; a missing/blocked mount-ID query fails the scan rather than silently substituting device numbers. This adds one descriptor query per entered directory, no mount table or new dependency. Reporting does not restrict cross-mount traversal, bypass exclusions, or affect canonical metadata.

Supported file fidelity is content, permission bits `0000` through `0777`, nanosecond modification time, and symlink topology. Setuid, setgid, and sticky bits are not recorded for regular files; restoring privilege bits without ownership fidelity would be unsafe. Whole-root support is explicitly a content archive, not a bootable or full-fidelity system image.

Not supported in the initial format:

- empty directory records;
- ownership, ACLs, xattrs, hardlink identity, device nodes, sockets, FIFOs, or other special files;
- built-in sudo orchestration;
- legacy backup formats.

Special files are skipped with visible counts. Broken symlinks and symlinks resolving outside `BACKUP_ROOT` are skipped with visible diagnostics. Directory symlinks resolving inside the root are preserved. A stored root-relative symlink target is recreated as the corresponding relative target from the symlink's parent, preserving topology beneath a different restore root. Never follow symlinks while opening source files or restore destinations.

Always exclude `$BACKUP_ROOT/.backup`. When root is `/`, additional default exclusions include at least `/dev`, `/proc`, `/run`, `/sys`, and `/tmp`; exclusions are explicit and auditable. Reject any snapshot in which a file or symlink path is an ancestor of another index path. Scan/read/stat failures are fatal. A zero-entry snapshot requires explicit `--allow-empty`; otherwise fail rather than committing a silent empty snapshot.

During add, native Git ignore rules apply both inside and outside repositories: nested `.gitignore` files, available `.git/info/exclude`, and configured global excludes. In a recognized Git worktree, tracked paths and their parent directories remain eligible even when an ignore pattern matches; untracked files remain eligible unless ignored. Backup's explicit exclusions take precedence. Ignored directories are pruned and each omitted file/directory is reported as `git-ignored`. Nested repositories, submodules, linked worktrees, and roots inside a worktree use their applicable Git rules. `.git` files/directories remain eligible regardless of Git ignore rules; excluding them requires the backup ignore file. External Git directories referenced by a gitfile are not implicitly added to the source set.

Absent or structurally invalid repository metadata uses a private temporary Git directory for pattern-only matching, without the source index or repository-local configuration. An unusable `.git` marker emits `git-ignore-untracked-fallback`; ignore rules then apply to all files, including any that were historically tracked. Source metadata is never repaired or modified. A nested marker establishes a new matching scope after its parent rules allow traversal. Outside repositories, matching starts at the backup root and inherits nested ignore files within it. Temporary matcher directories are private, excluded from the scan, and removed when the matcher closes.

Git ignore selection happens only at add; commit retains that exact path plan. One streaming `git check-ignore` process per active matching scope avoids per-path subprocesses and a duplicate path catalog. Its NUL-delimited responses are bounded to 64 KiB per field; ignore files are bounded to 16 MiB and Git marker/HEAD/common-directory text to 64 KiB. Missing metadata permits pattern-only matching, but read/permission errors do not. Unreadable ignore files, configuration/index errors in a recognized repository, failed commands, and oversized queries fail the scan rather than silently changing exclusion semantics. Source Git commands retain user ignore configuration but disable hooks, fsmonitor, optional locks, and network transports, and clear inherited repository/pathspec overrides. This is distinct from the metadata Git runner's stricter configuration isolation.

`backup add` is a planning scan, not the content-capture boundary. The last successful add fixes the exact lexical path set eligible for the revision plus provisional kinds, hashes, sizes, modes, mtimes, and symlink targets. A later commit never enumerates the source tree and never includes a path first created after add. Commit opens each planned path descriptor-relatively beneath `BACKUP_ROOT` without following any symlink component, captures its current supported kind, content, and metadata, and writes only those final observed values to canonical metadata. A planned path changed since add is captured in its current form and produces an informational warning; a disappeared, broken, outside-root, directory, or special path is omitted with a warning. Permission, I/O, unsafe traversal, and other errors remain fatal. If every planned path disappears or becomes unsupported, commit fails unless the plan was explicitly created with `add --allow-empty`.

For a regular file, commit records its size when opened, copies at most that many bytes once into a private mode-`0600` plaintext spool file, and hashes/counts the exact bytes copied. Later appends are deferred to the next revision; an earlier EOF after truncation yields the shorter bytes actually captured; concurrent in-place writes yield the exact one-pass byte sequence read. Detectable differences from add or changes during capture are warnings, never reasons to abandon an otherwise readable file or pack. The stable spool hash and size become the tar member identity, dedup decision, and final index values. Filesystem snapshots may be provided externally for point-in-time or application consistency but are not orchestrated by this program.

## Local staging and transaction protocol

Candidate and local operational state live beneath a fixed private directory recorded in `.git/info/exclude`, not a tracked `.gitignore`, and never in Git's index. Create its directories as `0700` and files as `0600`, use unique no-follow names and descriptor-relative operations, and fsync files plus containing directories. The committed checkout remains clean until commit finalization.

The operator must exclusively control the local metadata/operational namespace and its ancestors. The durable JSON store opens its directory without following a leaf symlink before applying permissions; temporary creation, publication, cleanup, reads, and publication fsync use the retained directory descriptor. This prevents that store from redirecting a write through a replaced directory pathname. It is localized correctness hardening, not protection of local state from a compromised same-user process or a guarantee that Git and every staging path tolerate hostile namespace replacement.

Source scanning and plaintext-spool cleanup each open an independent directory description for every enumeration and read entries in batches of 256. A reused root or spool must not inherit an exhausted directory offset from an earlier scan/cleanup. The durable JSON store has no reset/removal API; `backup reset` continues to use its existing transaction-aware cleanup path.

`backup init` is local preparation only. It creates an unborn Git SHA-256 repository, fixes the repository UUID, and writes the seven draft metadata files with empty catalogs, `.publickeys`, and `mirrors.tsv`. It requires no keys and does not read trusted remote configuration, construct an object client, fetch, push, or upload. Its output is `initialized<TAB>UUID` plus `publication<TAB>local-only`, not a commit ID or a mirror-completion claim. The local branch initially names `main`; first publication binds the branch from trusted configuration.

A small private `preparation.json` pins the exact initial `FORMAT` hash and identifies this intentionally unborn state. Before first publication, `add`, `diff`, and `reset` work locally without remotes or credentials. They use the normal bounded scanner and file-backed path plan against empty catalogs, reject unrelated metadata edits, preserve identity/recipient checks, and never guess that a repository missing its preparation record is fresh. Reset discards the plan, not initialization or configuration. `init` refuses every nonempty existing metadata directory; it never deletes one or resumes publication.

The first `backup commit` requires an add plan, nonempty valid recipient chains, and complete trusted Git/mirror configuration. It checks that mutable metadata still matches the add-time plan. If the planned `mirrors.tsv` is empty, this first commit fills it from the trusted mirror configuration; a nonempty table must already match exactly. Ignore/recipient edits still require another `add`. The selected source path set is unchanged even when configuration or source files are created after add.

First commit durably pins Git destination/branch before configuring `origin`, then internally creates and publishes the existing empty genesis and its full encrypted metadata bundle. Only after at least one mirror completes that base does it capture the saved first data plan and publish the ordinary snapshot/delta. The first command reports success for the selected snapshot, not for bootstrap alone. A disappeared/unsupported entire plan still fails unless add explicitly allowed emptiness; an explicitly empty plan may complete at genesis when its final metadata is identical. All committed-format rules remain unchanged, including empty genesis catalogs, at least one genesis mirror, and incremental later edges. No second operator commit command is needed on the healthy path.

The genesis transaction retains the exact first plan. Once genesis is complete, one atomic transaction-record replacement hands that plan to ordinary capture before removing the preparation marker; crashes on either side resume rather than losing the plan or reporting bootstrap as the data revision. `commit` resumes interrupted publication, not `init`. Uncertain/published Git pushes retain the existing conservative reset rules. Reset before a genesis push preserves local draft metadata; reset after the genesis-to-data handoff may abandon unpublished data work but never removes published genesis. Initial publication never adopts an existing remote repository's history. Mirror quarantine, mandatory primary publication, immutable upload acknowledgements, and one-individual-mirror completion apply unchanged.

**Accepted early local-setup manual-recovery exception:** interruption before `preparation.json` is durably written can leave a nonempty `.backup` that retry refuses. Git setup and some or all draft canonical files (including UUID/public recipients) may already exist. This invocation of local-only `init` has created no commit, transaction, remote genesis, or uploaded object, but the same directory/error can also represent damaged established state. Missing `origin` is normal for successful local preparation and is not evidence of corruption or freshness. Never infer disposability from an unborn HEAD or absent marker alone.

Use preservation-first manual recovery:

1. Stop competing operations; confirm the intended root and any already-selected remote namespaces against trusted configuration and deployment records.
2. Preserve the entire `.backup`, including `.git`, hidden operational state, refs, reflogs, objects, and draft configuration, in private storage without dereferencing unexpected symlinks. Do not start with deletion, reset, clean, or reinitialization.
3. Inspect file types, all loose/packed refs and objects (including unreachable objects), reflogs, canonical files, preparation state, and transactions. A valid completed local preparation should continue with `add`/`commit`; meaningful or ambiguous state requires targeted diagnosis, not another identity.
4. Where prior remote use is possible, inspect the exact trusted primary branch and mirrors read-only. Authentication failure, timeout, or unavailability does not prove emptiness. Existing history requires preserving/recovering its identity.
5. Only after positively identifying fresh unpublished setup residue, quarantine it under a unique non-overwriting private name and retry initialization, then restore the intended public recipient chains. Keep preserved/quarantined state outside the source tree or explicitly exclude it before add. Retain useful draft configuration and independently stored private key chains.

Git setup `HEAD`, `config`, exclusion file, and initial directories are fsynced before reporting local initialization or completing first remote binding; ordinary Git object/reference fsync hardening remains in force. This is localized setup durability, not custom journaling or a universal storage power-loss guarantee.

`backup add`:

- acquires the local repository lock and validates local preparation, or fetches/validates metadata base state after first publication;
- scans and hashes every included regular file to create a provisional, lexically path-sorted plan;
- validates and captures the exact candidate bytes of mutable tracked configuration (`ignore`, `.publickeys`, and `mirrors.tsv`), rejecting any unrelated dirty or untracked metadata worktree state;
- stages only the exact selected path set, provisional metadata used by `diff` and later warnings, configuration bytes, base commit (absent during local preparation), and `--allow-empty` choice—no plaintext payload or ciphertext;
- atomically replaces an earlier add-only plan so the normal workflow is repeated `add`, inspect `diff`, edit `ignore`, and `add` again;
- refuses to replace a transaction after commit has created durable payload progress;
- fsyncs staged state and does not upload or alter committed metadata;
- always reads every included regular file; do not add an mtime/size trust cache that can miss content changes.

`backup diff` compares the provisional add-time path plan with HEAD without materializing candidate files into the Git worktree. It is authoritative for path selection but provisional for content hashes, sizes, kinds, modes, mtimes, and symlink targets; the successful commit ID identifies the exact captured revision.

`backup commit` is a durable resumable state machine. It captures only planned paths in lexical order. It privately spools one complete regular file, uses the spool's exact hash and size for deduplication and tar framing, appends a new unique member immediately, and deletes the plaintext spool after the pack pipeline consumes it. The default spool is beneath private excluded operational state; a trusted local override may place it on another filesystem. Plaintext spool directories are `0700`, files are `0600`, all access is descriptor-confined/no-follow, stale temps are safely removed after restart, and the program makes no secure-deletion claim. Peak payload workspace is independent of total backup size but may be the largest captured individual file plus one ciphertext part and bounded metadata workspace. Preflight available bytes/inodes and retain explicit safety headroom; fail before an oversized capture rather than filling the filesystem or skipping the path.

Its small control manifest records paths, hashes, sizes, counters, and state—not embedded canonical blobs or ever-growing acknowledgement maps. Canonical candidate files and append-only bounded progress segments live as separately hashed/fsynced files. It records at least:

- base Git commit and add plan identity;
- hashes/sizes of canonical candidate files and completed-pack progress segments;
- per-mirror completion state and unresolved outcomes;
- local metadata commit;
- primary Git push confirmation;
- per-mirror metadata-delta completion.

Every transition is atomic, fsynced, idempotent, and safe to retry. Required ordering:

1. For each planned regular path not already deduplicated, capture one complete plaintext spool and append it to the current logical pack in add-plan path order; delete that spool as soon as the pack pipeline consumes it.
2. Stream encryption into one bounded fsynced ciphertext-part file at a time and upload it with create-only conditional writes to mirrors durably known complete through the base. Delete a local part only after at least one surviving candidate-complete mirror acknowledges it. The candidate-complete set is the intersection across every completed part and pack, never a union of partial mirrors.
3. After the encrypted stream ends and its final pack hash/part count are known, durably record the completed pack's exact index/object/pack rows and mirror completion, then advance the plan cursor. A pack becomes resumable progress only after one individual mirror has every part. A crash before that record restarts the whole pack; already uploaded parts are harmless immutable orphans. Do not persist or resume tar/zstd/encryption state inside a pack. One unusually large file may therefore be recopied and retransmitted after a crash.
4. After every planned path is processed, externally sort and merge bounded completed progress with the base catalogs to construct and validate exact final `index.tsv`, `objects.tsv`, and `packs.tsv`. Establish that at least one individual mirror has every pack part referenced by those candidate catalogs.
5. Atomically materialize metadata and make one local Git commit.
6. Create, encrypt, split, and fsync the incremental metadata Git bundle for `previous_commit..new_commit` into durable staging.
7. Fast-forward push the already-bundled commit to the primary metadata remote.
8. For mirrors that have the complete data revision, catch up any missing earlier metadata-chain edges, then upload the staged bundle parts and immutable completion manifest.
9. Report success only after at least one individual mirror has every currently referenced pack part and a complete valid metadata-bundle chain through the new commit.

Only an unambiguous successful create response, or a checksum audit of the exact expected size and checksum after an ambiguous response, counts as an upload acknowledgement. A timeout, disconnect, `409`, `412`, or other uncertain result never proves that the existing bytes are ours. Before metadata publication, if no mirror has unambiguously acknowledged a candidate key, atomically persist a fresh `object_id` and retry; once any mirror acknowledges a key, keep it canonical and leave other ambiguous mirrors lagging until audited. After the Git push, apply the same rule by creating a fresh persisted physical representation for ambiguous metadata-bundle parts or manifests; an uncertain completion-manifest result never counts as completion. Never infer object integrity from existence or a conditional-write conflict alone.

Persist a local, fsynced, Git-ignored completion ledger keyed by exact commit and mirror. An ordinary backup may extend a mirror recorded complete through its base commit; it must not guess after the ledger is lost or when every known-complete mirror is unavailable. Successful `verify HEAD` rebuilds this state, including for a single mirror; successful `sync` records both its fully audited source and destination without regressing a newer completion record. A historical audit never clears a current quarantine. The ledger is a resumability aid, never canonical metadata or a substitute for periodic verification.

Confirmed current-object corruption, or loss of previously acknowledged required objects/metadata chains, durably quarantines the affected mirror and invalidates all pre-incident completeness claims in one atomic ledger write. Ordinary backup publication pauses until a fresh audit establishes an individual mirror's complete current data catalog and metadata chain. Audit results used to resume must be newer than the incident, regardless of mirror visitation order. Healthy mirrors may then carry ordinary backups with a prominent degraded-redundancy diagnostic; damaged mirrors stay excluded until a successful full current audit or audited repair/sync. Reobserving an already quarantined mirror does not repeatedly revoke fresh evidence for healthy mirrors. Capture and candidate acknowledgements predating the incident require fresh checksum audits before reuse.

Timeouts, credentials/TLS failures, missing checksum capabilities, and ordinary mirror lag are not proof of corruption. Superseded historical data keys do not quarantine a compatible healthy current mapping, and an unusable metadata representation does not quarantine a mirror when another representation supplies a complete verified chain. Restore, sync, and data-repair reads also record conclusive failures of current data objects. The local incident state contains a counter, mirror quarantine set, and optional forward-repair anchor, not an unbounded per-object incident log. Operational state version 4 rejects older transaction/ledger versions; it does not migrate or discard them. Finish old staged transactions with their original binary before upgrading, retain the old ledger separately, and rebuild the new ledger through verification.

A Git push that succeeds before metadata-mirror completion leaves resumable finalization state; it is not reported as a complete successful backup until the mirror invariant holds. The primary Git fast-forward push is always mandatory: object mirrors are disaster-recovery replicas, not an alternate concurrency authority. If Git is unavailable, retain durable state and resume later rather than accepting an offline/divergent revision. Uploaded but unreferenced immutable objects are harmless and never deleted.

Accidental overlapping writers still meet the fast-forward/CAS boundary; this is a safety defense, not support for multiple authoritative owners. Once a Git push intent has been durably recorded, `reset` refuses while the outcome is unavailable, still at the base, or contains the candidate; it may abandon the candidate only when a different validated descendant of the base proves that the candidate permanently lost that boundary. No-op add/commit/reset operations succeed cleanly except that commit cannot hide an unfinished forward repair.

If an integrity incident makes a published pending revision impossible to finalize, an explicit `repair data` may advance through it. First obtain healthy repair bytes without altering pending staging, resolve/confirm the pending Git push and require its exact primary tip, then durably record a forward-repair anchor. Publish the pending revision's metadata bundle alone and checksum-verify its complete chain on one mirror before retiring its transaction. This preserves the exact published commit and recovery edge without reporting its damaged data revision successful. The durable anchor blocks ordinary backups across cleanup/restart gaps until a verified repair descendant completes. Primary Git publication remains mandatory, and `reset` never abandons the published revision.

A repair candidate is eligible only after fresh verification of its complete candidate data catalog plus its base metadata chain; it must not require a falsely healthy base data catalog. When several relocations are needed before any mirror can be complete, repeated `repair data` calls accumulate parts in the same unpublished repair candidate; retrying an already staged part reuses its durable bytes/key. No partial repair is reported successful. Once a repair has a local commit, resume it with `commit` (or use explicit forward repair if a new incident affects its published tip). Verification, restore, sync, and metadata repair remain available during pending publication; read operations validate the local accepted tip without trying to materialize another tip over the transaction. Metadata repair of the pending tip requires proof that its Git publication occurred. Successful full verification may finalize a pending revision through a healthy alternate metadata representation without fabricating acknowledgements for different staged bytes.

## Mirrors and self-contained metadata

A backup revision succeeds when **at least one individual mirror** contains every pack part referenced by the revision's catalogs and a complete valid metadata-bundle chain through that revision. A union of incomplete mirrors does not count.

Unavailable mirrors do not block success once this invariant is met. They are reported as lagging.

Every object mirror is independently recoverable through an immutable Git-bundle chain:

1. The first completed metadata revision on a mirror is a full encrypted Git bundle; each later revision is an encrypted incremental bundle for exactly `previous_commit..new_commit`.
2. Bundle ciphertext is split into bounded immutable parts. A small, strictly size-bounded plaintext completion manifest uses the same raw tab/LF canonical text rules, with an exact ordered set of tagged singleton rows followed by contiguous numbered `part` rows—no JSON or quoting. It records repository UUID, manifest format, sequence, base commit (`-` for a full bundle), tip commit, full-versus-incremental kind, complete encrypted-bundle BLAKE2b and size, and each part's count, 32-hex random object ID, BLAKE2b/SHA-256/MD5 hashes, and size.
3. Derive part keys as `metadata/parts/<part_blake2b>/<object_id>` and manifest keys as `metadata/manifests/<tip_commit>/<manifest_blake2b>/<object_id>`; do not store redundant complete keys inside the manifest. The repeated tip segment is a deliberate validated index so anchored `--tip` recovery need not inspect unrelated or attacker-flooded manifests. All keys are create-only. Upload all bundle parts first and the hash-addressed manifest last; the manifest is the sole completion marker. Cloud verification may fetch these bounded manifests, but never pack bodies or encrypted bundle-part bodies.
4. Recovery lists and size-bounds candidate manifests, verifies their key/content hash and schema, validates every required part, constructs every valid chain, and decrypts/applies bundles only inside a fresh private quarantine repository with hooks/filters disabled. Host resource containment is the operator's responsibility (see **Restore safety**), not a sandbox enforced by the binary. It accepts a chain only after exact commit IDs, prerequisites, trees, and all metadata transitions validate, then atomically publishes the recovered repository. The latest single chain is only the ordinary default; recovery can list every verified commit and `--tip COMMIT` reconstructs exactly an earlier tip. If more than one maximal commit chain exists, report every tip and require an explicit choice rather than silently choosing a fork.
5. Multiple immutable physical representations of the same full bundle or base/tip edge are allowed so corrupt metadata manifests or parts can be relocated. They are equivalent only when decrypting/applying them reconstructs and validates the exact declared Git commit graph and tip; alternate physical representations of one edge are not metadata-history forks.

Recovery extends one private Git repository per attempt rather than copying the accepted graph for every bundle. After validating the bundle header and prerequisites, it streams the pack through native `git index-pack --strict`, then checks connectivity and rejects every unreachable object at that exact revision. A final full strict Git check rehashes all stored objects before canonical history validation and publication; previously accepted local object bodies are not rehashed after every edge. This preserves final integrity while avoiding repeated inflation of historical metadata blobs. The explicit strict indexer also works with Git 2.36, whose bundle-fetch transport did not honor `fetch.fsckObjects`.

A failed import discards its entire private repository and replays from the full bundle using another physical representation. Rejected representations are not retried within that logical path, and one path is capped at 10,000 attempts. Automatic Git maintenance is disabled in these private repositories so detached repacking cannot race validation or cleanup. At most one verified candidate is retained alongside the current attempt; listing retains only commit IDs. Publication renames the exact verified repository from staging on the destination filesystem, without another remote download or reconstruction. Other temporary validation work may still use `TMPDIR`; operator-owned aggregate resource containment remains required.

Structural validity does not prove that a compromised client intended a good snapshot. Every successful commit reports its exact 64-hex Git SHA-256 ID and the names of mirrors complete through it; retain those anchors in external operational logs. After suspected compromise, recovery never assumes the newest linear extension is trustworthy: inspect history and select a last-known-good `--tip` explicitly.

Do not upload a complete ever-growing Git bundle after every revision. Do not add periodic full checkpoints initially; they can be added later without deleting the delta chain if demonstrated necessary.

`backup sync` catches up a missing/lagging mirror from a healthy mirror by creating absent immutable keys and metadata deltas. It never overwrites or deletes. It uses each mirror's ordinary profile: reads at the source, and reads plus immutable creates at the destination. An existing destination key is checksum-verified rather than trusted from `412` or existence.

Mirror availability is operational state, not duplicated into every canonical object row. Every mirror uses the same logical object keys. Canonical metadata never records provider-specific S3 VersionIds. AWS versioning/Object Lock may be deployed as defense in depth, but portability and restore rely on provider-enforced immutability, hashes, and immutable relocation.

A backend is not production-eligible merely because ordinary uploads work. AWS S3 and R2 require the real cloud contract with the exact ordinary production credential for each mirror and a retained immutable probe. The Docker contract accepts the `backup-server` binary; its deployed TLS endpoint, credentials, restart, verification, and restore are separate gates. Contracts must prove conditional creation and checksum persistence, then attempt unconditional/copy/multipart overwrite, ordinary/version/batch deletion, role escalation, SSE-C, and every applicable bucket-policy/public-access/encryption/lifecycle/immutability/versioning mutation without changing the probe. Enforcement is backend-specific:

- `backup-server`: its narrow server protocol itself requires create-only PUT and exposes no destructive API.
- AWS S3: a dedicated read/list/create IAM policy plus bucket policy denies deletion and rejects object creation without `If-None-Match: *`. Libaws converges default SSE-S3 (`AES256`) and blocks SSE-C in the bucket encryption configuration; the contract proves the default with a probe that omits the encryption request header, while the backup client explicitly requests and verifies `AES256` for every object. Encryption remains independent of append-only enforcement: the bucket policy does not require an encryption request header or deny an explicit SSE-KMS request, neither of which permits overwrite or deletion. Versioning/Object Lock may add defense in depth.
- Cloudflare R2: because it has no equivalent conditional-write bucket policy and its ordinary long-lived object-write role is not create-only, a dedicated bucket or complete backup prefix must have an enabled indefinite R2 bucket-lock rule. Contract acceptance reads the native Bucket Lock API, requires that rule to cover the exact backup namespace, and proves neither the ordinary S3 access-key ID nor its secret authenticates to that API. The native account-token API must also deny token issuance and changes to the client token policy; R2 lifecycle, public-domain, and bucket deletion attempts must fail by authentication/authorization, not merely malformed bodies. The contract recognizes specific Cloudflare authentication error codes, including HTTP 400; a generic 400 never proves denial. The client receives only a bucket-scoped object credential, never a bucket-configuration/admin credential. The lock, not honest client behavior, is the overwrite/delete boundary. SSE-C overwrite must also fail against the locked probe. Unlike the AWS deployment, R2 is not required to reject SSE-C on new attacker-created keys: such keys cannot alter existing protected objects, and creating unusable new objects is already within the accepted compromised-client threat model.

Any backend that cannot pass the destructive negative tests is rejected for production use rather than silently weakening the threat model.

Until the release gate, a configured AWS S3 or R2 mirror may be used for pre-release testing and may satisfy the ordinary runtime success threshold when it alone contains the complete revision, even if its destructive contract has not passed yet. This is an operational testing exception, not a weaker production design: such a revision is test data, the client does not claim that the mirror is ransomware-resistant, and every configured production backend must pass its exact contract before the first production backup is accepted. The runtime completion rule remains backend-agnostic—any one complete individual mirror is enough—and does not encode deployment-policy state into the repository format.

## Verification and repair

`backup verify` validates mirrors independently. It accepts `--minimum-mirrors=N`, default `1`, and exits successfully only when at least `N` individual mirrors pass their backend-appropriate checksum verification. Always report all unavailable, incomplete, corrupt, or unverifiable mirrors even when the threshold passes.

Verification always validates canonical metadata and cross-file invariants plus the complete metadata-manifest chain through the selected tip. Required-object verification is backend-specific so checking large cloud mirrors does not transfer their bodies:

- **AWS S3:** upload an explicit full-object SHA-256 and later request checksum mode with `HeadObject`; require matching size and provider-returned SHA-256, and require `FULL_OBJECT` when checksum type is returned. The wire checksum is Base64 of the digest while canonical TSV hashes are lowercase hex. A documented single-PUT MD5/ETag path may be used only for the exact encryption/upload mode whose provider contract guarantees it; never infer MD5 merely from ETag shape.
- **Cloudflare R2:** its real-account contract suite must establish which full-object checksum is rejected on upload mismatch, persisted, and returned by `HeadObject` without a body. Pin that capability to backend kind and fail closed if it is absent or changes. Never assume AWS checksum or ETag semantics merely because R2 exposes an S3-compatible API.
- **Remote `backup server`:** an authenticated checksum-enabled HEAD/verification request makes the server read and hash the local object itself, then returns standard full-object SHA-256 (`x-amz-checksum-sha256`, Base64, with `FULL_OBJECT`) and size metadata. It may additionally return its documented single-PUT MD5 as ETag. The object body is not transmitted.
- **Locally accessible backup-server data root/local disk:** read each required object locally and recompute BLAKE2b/size directly.
- **Metadata completion manifests:** cloud verification may `GetObject` only for these strictly bounded plaintext manifests, then verify their hash-addressed key and contents. It still uses HEAD/checksum metadata for pack parts and encrypted metadata-bundle parts and never downloads those bodies merely to verify them.

A mirror counts toward `--minimum-mirrors` only when its manifest chain is complete and valid and every currently required pack and bundle-part object is present and agrees with the strongest trustworthy checksum that backend exposes. If a provider exposes neither a trustworthy full-object SHA-256 nor a documented MD5 for the exact upload mode, verification reports that mirror as unverifiable rather than silently falling back to existence/size.

Restore itself performs complete ciphertext, encryption-authentication, tar-member, and plaintext-hash verification for the selected content. Full decrypt verification without restore applies only when the object-store data root is directly accessible as a local filesystem and the verifier can read the stored bytes itself. Every protocol backend—including `backup-server`, AWS S3, and R2—is checksum-only: `backup-server` hashes bytes internally for checksum-enabled HEAD but does not transmit them, just as S3/R2 verification does not download object bodies.

Normal verification evaluates only objects referenced by the current catalogs. Superseded corrupt objects may be reported separately but do not make current state unhealthy.

Bit-flip repair is by immutable relocation, never overwrite:

1. Obtain healthy exact ciphertext bytes from another mirror or repaired lower storage layer.
2. Verify their expected hash and size.
3. Persist and upload a fresh key containing the same ciphertext hash plus a new object ID.
4. Replace the affected `packs.tsv` row in a new fast-forward Git commit.
5. Complete that metadata revision on at least one mirror.
6. Catch up other mirrors later.
7. Leave the corrupt old object untouched.

If no healthy copy exists, hashes cannot reconstruct lost pack bytes and data-pack repair fails honestly. For local disks, `~/repos/mirror` remains the lower-layer redundancy/repair mechanism. S3/R2 provide their own media-integrity systems, while backup still performs end-to-end verification.

Metadata-bundle repair does not modify canonical Git catalogs. Newly regenerated representations always use today's validated HEAD recipient chains, even for a historical Git edge; copying existing ciphertext preserves its original recipients. It may copy a healthy exact representation, or—when the exact validated Git base/tip object graph is available—generate, encrypt, split, and publish a new immutable representation for the same edge. Accept it only after recovery reconstructs the exact declared commits; leave every old manifest and part untouched. If neither healthy representation nor the required Git objects survive, repair fails honestly.

The ordinary client has no effective overwrite/delete capability against existing protected objects. For data packs, `backup repair` uses the ordinary profiles to read a healthy source and create immutable objects at each destination, then creates a normal fast-forward relocation commit. For metadata bundles it publishes only the alternate physical representation described above and creates no Git-history edge.

## Restore safety

**Operator-owned resource containment:** when working with potentially malicious backups, the operator must run restore, metadata recovery/import, and recovery listing (`backup recover --list`) in an appropriately resource-bounded environment covering the entire command and its descendants. Recovery listing decrypts/imports candidate chains; it is not just a manifest listing. `--tip` narrows discovery but does not make candidate representations resource-safe. Use enforced aggregate memory/swap limits, CPU/wall-time controls with descendant termination, and storage with aggregate byte/inode bounds. Cover temporary work (`TMPDIR`, including history-validation workspaces) and the destination filesystem. A private directory or container bind mount alone is not a resource limit; provisioning and checking the environment are operational responsibilities, not automatic backup behavior. Budgets must accommodate legitimate metadata/history sizes and be adjustable without changing the backup format.

Checksums, encryption authentication, bounded parsing, private Git quarantine, and pre-publication validation remain mandatory integrity protections. They do not establish benign intent or bound all resource consumption: Git can allocate, inflate, reconstruct deltas, and traverse graphs before canonical validation finishes. Free-space preflights estimate capacity; they do not reserve it or enforce quotas. The binary does not enforce aggregate subprocess memory/CPU/disk limits or process-tree deadlines. Resource containment is the operator’s responsibility; the binary provides no sandbox, runtime containment enforcement, or automatic provisioning.

Restore treats all metadata and object bytes as untrusted. The operator must exclusively control the destination namespace from planning through publication, including ancestor directories that could rename the target or its parents. Concurrent destination writers—including other same-user processes—are unsupported. In particular, do not restore as root into directories an untrusted user can modify. Private file modes and no-follow traversal do not enforce this operational requirement. The regular-file pre-publication inode check detects temporary-entry replacement during copying as defense in depth; it is not an atomic guarantee against a writer racing the subsequent rename. This boundary applies to symlink publication as well.

Required behavior:

- resolve the requested snapshot revision and optional catalog revision once to exact commit IDs and print both;
- validate all canonical metadata before object reads;
- restore exactly the rows whose paths match the requested regex; do not implicitly add a symlink's target;
- `--dry-run` performs no object reads or decryption and reports new/overwrite/conflict paths;
- download/decrypt/decompress all selected regular-file content into bounded local staging, verifying ciphertext size/hash, secretstream final authentication, tar structure/member set, plaintext hashes, and expected sizes before publishing any selected path;
- never use tar path extraction: members are hashes and are copied through controlled code;
- use descriptor-relative no-follow path operations beneath the target root;
- reject parent symlinks, traversal, special destination types, and unsafe file/directory conflicts;
- refuse every existing indexed leaf by default; replacement requires explicit `--overwrite`. Existing safe parent directories are allowed and never chmodded; missing parents are created descriptor-relatively as `0700`, fsynced, and carry no inferred historical metadata;
- prepare each verified regular-file row as a separate unique no-follow temp inode in its destination directory—never hardlink restored paths merely because content is deduplicated—apply mode and `mtime_ns`, fsync it, atomically rename it into place, then fsync the containing directory;
- create each symlink through a unique temporary name only after all regular-file staging/verification, atomically rename it into place, and fsync the containing directory;
- never truncate an existing destination before verification;
- never delete unrelated destination files;
- each published path is complete and verified, but publication is not an operation-wide filesystem transaction: a late parent-creation, rename, or symlink-publication failure may leave an exact subset already published. Report that subset and every remaining path precisely; do not add rollback/journaling complexity.

## Production `backup server`

The server is production software and the primary object-backend test mechanism, but deliberately implements only capabilities backup needs. Production requires supplied TLS material and one ordinary read/list/create credential:

```sh
export BACKUP_SERVER_ACCESS_KEY=...
export BACKUP_SERVER_SECRET_KEY=...
backup server \
  --listen :8443 \
  --data-root /var/lib/backup \
  --bucket backup \
  --prefix repository \
  --region us-east-1 \
  --tls-cert /etc/backup/tls.crt \
  --tls-key /etc/backup/tls.key
```

Scope:

- one configured bucket and one data root per server;
- path-style HTTPS only;
- request bodies are bounded to 1 GiB by default, matching the client's default ordinary-object part ceiling;
- SigV4 Authorization-header authentication with a fixed `Content-Length` and lowercase-hex SHA-256 signed payload;
- require every security-relevant present header in `SignedHeaders`, including `host`, nonzero `content-length`, `if-none-match`, `content-md5`, and every `x-amz-*` header; reject a required checksum, conditional, date, token, or checksum-mode header if it is unsigned;
- reject `UNSIGNED-PAYLOAD`, every `STREAMING-*` mode, `aws-chunked`, presigned query authentication, and missing/invalid payload hashes;
- `PutObject`, `GetObject`, `HeadObject`, and `ListObjectsV2` only;
- no DELETE, overwrite, multipart, CopyObject, or generic S3 features;
- every PUT requires signed `If-None-Match: *`, `Content-MD5`, and full-object `x-amz-checksum-sha256`; omission fails, and an existing key is never treated as writable;
- one authenticated read/list/create credential;
- server compromise is outside the threat boundary.

The server keeps independent sorted in-memory listing indexes for the logical key classes `objects/`, `metadata/parts/`, and `metadata/manifests/`, each with an accepted ceiling of 1,000,000 keys. Creating key 1,000,001 remains durable and known-key GET/HEAD continue to work, but every ListObjectsV2 request matching that class then fails; restart rescans the same immutable files and preserves the overflow result. Other key classes remain independently listable. This deliberately bounds memory rather than risking OOM: representative current key shapes retain about 193 MiB, 193 MiB, and 269 MiB respectively near the three ceilings, or about 654 MiB together before Go/runtime and merge headroom. A compromised writer can therefore consume enough keys/inodes to deny discovery—especially by flooding `metadata/manifests/`—which is an accepted capacity/availability attack under this threat model, not a data-integrity failure. Use a dedicated data root, monitor per-class key and free-inode counts, alert well before the ceiling, and retain external capacity monitoring. Under defaults, one million ordinary data-part keys corresponds roughly to 95 TiB of unique plaintext at the 100 MiB pack target, or ten billion tiny unique files at the 10,000-member pack limit; normal initial backups should remain far below it.

Durable create path:

1. Fully authenticate request headers and confine/validate bucket and key.
2. Write the body to an invisible temp file beneath the data filesystem.
3. Verify the signed payload SHA-256, fixed content length, object-key BLAKE2b, all recorded provider checksums, and request limits.
4. fsync the file.
5. Atomically install it without replacement under descriptor-relative/no-follow confinement.
6. fsync the containing directory.
7. Return success only afterward.

The server acquires an exclusive process lock for its data root before serving. Temporary uploads live in a dedicated `0700` internal directory on the same filesystem, are never addressable/listed as objects, and use random `0600` no-follow files. Failed requests remove their temp; after acquiring the root lock, startup safely removes stale regular temps and fails closed on unexpected types or cleanup errors.

Concurrent PUTs for the same key yield one creator and immutable conflicts for the rest. Failed auth, malformed/truncated bodies, client disconnects, disk-full conditions, and crashes never publish partial final objects. GET/HEAD never follow backend symlinks. An authenticated `HeadObject` with checksum mode enabled must stream the stored file locally, recompute and check key-embedded BLAKE2b plus SHA-256, MD5, and size, then return only standard full-object checksum metadata—never the body—so remote verification detects disk corruption without network transfer of object bytes. A conclusive stored-content mismatch returns HTTP 500 with `X-Backup-Integrity: corrupt`, because HEAD has no XML error body. Only the pinned `backup-server` backend interprets this header as integrity evidence; generic 500 responses and local read/I/O failures remain unavailability, not proof of corruption.

Security requirements include strict key grammar, no path joining from untrusted strings, constant-time signature comparison, configured-region enforcement, request-date freshness, bounded headers/body/time, TLS 1.2+, HTTP server timeouts, graceful shutdown, structured audit logs, and private-key files created/mode-checked as `0600`. Self-signed certificate generation is explicit development/test behavior only.

Each handled request emits one structured log with its actual response status. Internal failures retain their underlying operator-side cause while the public internal-error response stays generic. A failure after response headers were sent logs that original status at error level, without rewriting the response or appending an XML error. Failed error-response writes are also logged. Free-text request-log fields redact literal configured credentials and received Authorization/security-token values plus their standard URL-path-escaped forms; this is known-value redaction, not arbitrary secret discovery. Structured encoding escapes control characters, and raw request headers are never deliberately logged.

## `git-remote-aws` integration

Use the existing public `git-remote-aws` project and preserve readability of its existing repositories, keys, ciphertext, and S3/DynamoDB object layout. The shared key-chain feature intentionally changes key configuration and disjoint secret-source selection, not the encrypted wire format or storage protocol. Backup verifies that its candidate commit is the current local metadata branch, then pushes `refs/heads/<branch>:refs/heads/<branch>` because the helper accepts branch rather than raw commit-ID sources. The helper reads `.publickeys` from the exact commit being pushed, selects chain tips for encryption, and checks retained-chain extensions against the previously published tip. A previously published commit with no `.publickeys` entry adopts the selected tip policy; a present empty, malformed, or non-regular entry fails rather than masquerading as absence. This helper compatibility case does not relax backup’s canonical seven-blob history. It rejects staged/unstaged recipient edits, including during no-op push discovery; read-only fetch/clone remain available. Backup creates commit trees directly without a Git index; an absent index contains no staged entries, but an existing index must agree with the pushed policy, and the actual working recipient file must always match the commit. Before encryption/upload the helper verifies the generated bundle's advertised tip agrees with the commit used for ancestry, identity, and recipients; a concurrent local branch advance fails rather than publishing a mismatched bundle. Backup validates every metadata-history transition, including recipient chains. Its S3/DynamoDB state remains only the mandatory concurrency authority, while the object-mirror bundle chain provides disaster recovery.

## Operator commands

Initialize locally with no keys or remote required, then populate `.backup/.publickeys` from independently retained personal public chains:

```sh
backup init --root /data
# Edit /data/.backup/.publickeys with your public recipient chains.
```

Edit `.backup/ignore` and any additional recipients, then create and inspect a path plan locally. Configure the trusted Git remote and mirrors before the first commit, which publishes genesis and the selected snapshot together as one operator operation:

```sh
backup add --root /data
backup diff --root /data
backup commit --root /data
```

Optional operational controls include `--spool-directory` for a trusted alternate plaintext-spool parent and `--space-reserve-bytes` for retained free-space headroom.

Find paths, or discard an unpublished transaction when the transaction rules permit it:

```sh
backup find --root /data REGEX HEAD
backup reset --root /data
```

Verify and restore with an eligible historical recipient secret chain:

```sh
export GIT_REMOTE_AWS_SECRETKEY_CMD=/path/to/your-secret-loader
backup verify --root /data --minimum-mirrors 1
backup restore --root /data --target /safe/restore '^\./home/' HEAD
```

Recover metadata without the primary Git remote, synchronize mirrors, or repair immutable representations:

```sh
backup recover --root /data --mirror local --list
backup recover --root /data --mirror local --tip COMMIT --destination /safe/recovered.git
backup sync --root /data --source local --destination aws
backup repair data --root /data --source aws PACK_HASH PART_NUMBER
backup repair metadata --root /data --destination local --revision COMMIT
```

Recovery and metadata repair require an eligible recipient secret key.

After losing the primary Git service, follow [Restore from recovered metadata](docs/recovery-restore.md) before trying to restore files. `recover` publishes a validated bare repository with `refs/backup/recovered-tip`, not a managed checkout. The tested manual procedure checks the exact external anchor, promotes a branch/HEAD without replacing existing history, makes a fresh checkout, preserves trusted mirror pins while explicitly repinning the local metadata source, and restores using only that recovered metadata and a surviving mirror. Do not run `init`, reuse damaged staging, or treat rescue setup as permission to resume production writes. The original source tree and primary may remain unavailable throughout; production takeover still requires retiring the old writer, restoring the mandatory primary authority, and freshly rebuilding the ledger through verification.

Errors are concise stderr messages with nonzero status, not Go panics or stack traces; help exits successfully. Escape control characters in every untrusted path/key/error before terminal output, use structured encodings for machine/audit logs, and never log authorization headers, credentials, recipient secrets, or raw key material.

## Testing requirements

Cloud-free executable/PTY secret-loader regressions require Python 3.8 or newer; they use synthetic keys and exercise both actual CLIs. Parser-only key-chain cases live in go-libsodium; backup tests its metadata and application boundaries.

Run the cloud-free release checks and fuzz campaigns with:

```sh
make check                # mandatory lint, coverage, race detector, and vet
make fuzz                 # ten seconds per fuzz target
make fuzz FUZZ_TIME=1m    # longer pre-release campaign
```

`make check` fails closed if `staticcheck`, `ineffassign`, `errcheck`, `bodyclose`, or `nargs` is unavailable and runs every linter before tests. It is deterministic and requires no cloud account. Coverage and race runs each allow 30 minutes per Go test package, accommodating fsync-heavy state-machine tests on contended storage without disabling durability or changing assertions. Fuzz seed corpora run during ordinary tests; `make fuzz` performs mutation campaigns against actual canonical parsers, path/key grammars, local configuration, tar/pack readers, and SigV4 request parsing. Pack fuzzing includes a valid ciphertext seed with a fixed public test-only recipient for replay, plus authenticated-input mutations of tar or compressed bytes before real encryption. Positive seed controls must deliver the expected plaintext; authentication is never bypassed.

The production server runs inside Docker while tests and the real backup client run outside it.

The Docker integration suite must:

- build/run the real server image as non-root;
- use a separate persistent mounted data volume;
- use a generated test CA and normal TLS verification, never insecure-skip;
- use random host ports and the same ordinary credential for upload/read/list;
- run the real client against the container;
- kill/restart the server against the same volume;
- exercise concurrent creates, retries, lost responses, malformed/truncated bodies, traversal, backend symlinks, disk/full-write failures, immutability, fsync/restart durability, listing, and auth failures.

Run whole-root client tests in an isolated client container, with the server in a separate container. The unified suite first runs `make check`, then the real Docker-server and ephemeral AWS contracts normally and under the race detector:

```sh
# Requires Docker, administrator AWS credentials, a region, and this account guard.
export LIBAWS_TEST_ACCOUNT=123456789012
make integration
# Set LIBAWS=/path/to/libaws when the reviewed binary is not on PATH.
```

The harness validates Docker and the guarded scratch account, completes the observable Docker build before AWS mutation, instantiates the checked-in `infra.yaml` under unique names, gives tests only the generated ordinary client credential, and removes the user, every object version, and the bucket after success or failure.

R2 joins only when explicitly enabled after an indefinite Bucket Lock rule protects the entire test prefix:

```sh
# Set BACKUP_R2_CONTRACT_{BUCKET,REGION,ACCESS_KEY,
# SECRET_KEY,ENDPOINT,ACCOUNT_ID,
# LOCK_AUDIT_TOKEN}; PREFIX and JURISDICTION are optional.
BACKUP_R2_CONTRACT=1 make integration
```

R2 uses one bucket-scoped Object Read & Write credential plus a separate read-only control-plane audit token and retains its successful immutable probes because libaws does not provision that control plane. Its lock audit checks the configured backup namespace independently of random probe placement; an empty configured prefix requires bucket-wide protection. Cloud-free regressions exercise that same coverage check, including rejection of probe-only locks; they do not substitute for the live deployment contract. Native control-plane authentication-negative requests may be rate limited: the contract retries HTTP 429 with bounded backoff but never accepts it as protection evidence. R2 Bucket Lock also rejects aborts of multipart-overwrite probes, so tiny incomplete uploads can remain with the retained probes; never disable protection merely to clean up an acceptance test. The production backup client does not use multipart.

Both cloud contracts also run the real CLI with one ordinary profile: genesis, two data revisions, checksum verification, broad and selected historical restores with fidelity checks, and latest plus anchored-genesis metadata recovery while the primary Git remote is unavailable. Set `BACKUP_CONTRACT_EVIDENCE_DIR` to retain private per-run workspaces, ordinary credentials, and generated fixture recovery secrets; without it, local fixtures are temporary and the retained encrypted cloud test objects lose those test keys. These synthetic revisions are deployment tests, not production backups.

Additional required coverage:

- official independent AWS SigV4 known-answer vectors rather than test generators sharing production logic, plus rejection of every unsigned security-relevant header;
- parser/path fuzzing plus golden byte fixtures for every canonical text format and deterministic POSIX-PAX headers, including the large-file PAX `size` path;
- crash/restart injection after every commit-state transition;
- partial multi-object/multi-mirror uploads, lost responses, `409`/`412` handling, proof that conflicts never count as acknowledgement without audit, fresh-key retry, and lost/rebuilt local completion-ledger state;
- Git commit/push conflicts, stale clones, malicious trees/modes/extra paths/merge histories, sanitized Git execution, transition validation from genesis, compatibility with the unchanged public `git-remote-aws` helper, and recovery from an object mirror when that primary metadata service is absent or corrupt;
- scan-time file mutation, permission/read failures, unexpected empty scans, and large bounded-memory files;
- spaces, Unicode policy, modes, empty files, file/directory/broken/outside-root symlinks, duplicate content restored as independent inodes, deletion snapshots, default snapshot-pinned historical restores, explicit compatible `--catalog-revision` relocation fallback, rejection of incompatible/non-descendant catalogs, and no-op operations;
- corrupt/truncated/wrong-recipient/compression-bomb/object-substitution inputs;
- proof that content/metadata verification failures occur before publication and leave all destinations unchanged, while injected publication failures leave only complete verified paths and report the exact published subset; proof that no restore can escape through destination symlinks;
- bit-flip relocation, alternate metadata-bundle representation, mirror catch-up, metadata recovery from one mirror with the primary Git remote absent, and explicit recovery to an externally anchored earlier tip after a valid malicious linear extension;
- every provider contract specified above, including wrong-checksum rejection, persisted no-body checksum HEAD, and all destructive ordinary-client attempts without changing the probe;
- proof that S3/R2 verification fetches only bounded hash-addressed plaintext completion manifests and otherwise uses provider checksum metadata—never pack or encrypted bundle-part `GetObject`; plus proof that local-server verification detects a corrupted file while returning no body.

Tests must exercise actual system code. Protocol tests use official vectors or independent clients, not a reimplementation of the same production functions.

## AWS deployment and exact production acceptance

`infra.yaml` implements the AWS enforcement contract above with a dedicated private, versioned bucket and one read/list/create IAM user. Infrastructure convergence never creates credentials; provision with administrator credentials, then create the user's sole API key:

```sh
export BACKUP_AWS_INFRASET=backup-production
export BACKUP_AWS_BUCKET=globally-unique-backup-bucket
export BACKUP_AWS_USER=backup-production-client

libaws infra-ensure ./infra.yaml --preview
libaws infra-ensure ./infra.yaml
libaws iam-ensure-user-api-key "$BACKUP_AWS_USER"
```

The key command prints the secret only when it creates the user's sole key. Store the values in the trusted profile used by `.backup-config`. `libaws infra-rm ./infra.yaml` is deliberately destructive: it revokes the user and deletes every bucket object and version. Do not converge this new definition over an established dual-user deployment as an implicit migration; provision/review the intended single client principal and retire obsolete credentials explicitly.

The disposable deployment used by `make integration` validates the infrastructure definition, not an existing production bucket. Before the bucket contains production data, inspect its policy and run the destructive contract with that bucket's ordinary credentials—never administrator credentials. The test uses fresh random object keys, but deliberately submits destructive and bucket-wide control-plane requests that must be denied:

```bash
set -euo pipefail

export BACKUP_AWS_CONTRACT=1
export BACKUP_AWS_CONTRACT_BUCKET=globally-unique-production-bucket
export BACKUP_AWS_CONTRACT_REGION=ap-northeast-1
export BACKUP_AWS_CONTRACT_PREFIX='' # or the exact configured production prefix
export BACKUP_AWS_CONTRACT_USER=backup-production-client # exact IAM user, checked with STS
export BACKUP_AWS_CONTRACT_ACCESS_KEY=...
export BACKUP_AWS_CONTRACT_SECRET_KEY=...
unset BACKUP_AWS_CONTRACT_SESSION_TOKEN
# Export BACKUP_AWS_CONTRACT_SESSION_TOKEN after this when using temporary IAM-user credentials.
unset BACKUP_AWS_CONTRACT_ENDPOINT

# Prevent fallback to ambient credentials, endpoint overrides, or custom CA roots.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
unset AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SECURITY_TOKEN
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION AWS_DEFAULT_REGION
unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME
unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
unset AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case "$name" in AWS_ENDPOINT_URL | AWS_ENDPOINT_URL_*) unset "$name" ;; esac
done < <(env -0)
unset AWS_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_EC2_METADATA_DISABLED=true AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
export AWS_USE_FIPS_ENDPOINT=false AWS_USE_DUALSTACK_ENDPOINT=false

umask 077
evidence_dir=${BACKUP_CONTRACT_EVIDENCE_DIR:-"$HOME/.config/backup/contracts"}
mkdir -p -- "$evidence_dir"
evidence="$evidence_dir/aws-production-$(date -u +%Y%m%dT%H%M%SZ).log"
go test ./integration -run '^TestAWSCloudContract$' -count=1 -v 2>&1 | tee "$evidence"
printf 'evidence: %s\n' "$evidence"
```

A passing run repeatedly checksum-audits its probes after every denied attack and prints their exact `s3://` URIs. The direct test intentionally leaves those immutable probes. Preserve the private log and externally record the passing run and probe URI. The Docker software contract likewise does not accept a deployed instance: separately confirm its exact TLS endpoint and ordinary read/list/create credential, restart it against the same data root, and repeat verification and restore; no second destructive protocol suite is required.

## Dependency status

`go.mod` is the authoritative dependency version list. The module-level OSV `GO-2026-5932` finding concerns `golang.org/x/crypto/openpgp`; backup and go-libsodium import only `blake2b`. This is a package-applicability exception, not a suppressed vulnerability in reachable code. Reassess it when imports or dependencies change. Review Socket network/filesystem/environment capability warnings against actual usage.

## Removal/non-goals

Remove rather than carry forward:

- old Bash/Python commands and cloud-coupled Python tests;
- lz4 format support;
- BACKUP_FS-specific client code and R2 wrapper code;
- generic S3-server aspirations;
- streaming/aws-chunked/unsigned SigV4 payload modes;
- provider-specific VersionId metadata;
- multipart upload support;
- file-level rolling/chunk deduplication;
- overwrite/delete/garbage-collection APIs;
- migration and legacy compatibility;
- commit-message metadata;
- automatic in-place corruption repair;
- automatic privilege escalation;
- wrappers around ordinary text editor, cat, or Git commands.

Storage is intentionally append-only and grows forever. Capacity planning and provisioning are operational responsibilities.

## Backend checksum behavior

R2 rejects a wrong full-object SHA-256, persists and returns a valid digest through checksum-mode `HeadObject` without a body, and omits checksum type. R2 rejects simultaneous explicit SHA-256 and `Content-MD5`, so its uploads send SHA-256 only while AWS and `backup-server` receive both. The live cloud contract must confirm this behavior for each deployment.

## Release and first-backup gates

These are deployment acceptance gates, not implementation prerequisites or new features. The first production revision is not accepted until all have succeeded:

1. Complete `make integration`, the separate [AWS Git-primary gate](docs/git-primary-contract.md) (`make integration-git-remote`), and the exact-production contract runbook above for every configured cloud backend; retain and recheck each immutable probe. The Git-primary gate requires the independent pre-keychain helper artifact and provisions/cleans its own guarded scratch S3/DynamoDB resources, without expanding mirror credentials.
2. Complete the revision on at least two individual mirrors when two are configured.
3. Verify each configured mirror using its backend-appropriate trustworthy checksum path.
4. Perform full local decrypt/decompress/plaintext verification.
5. Recover metadata solely from one object mirror with the primary Git remote unavailable, both at the latest tip and at an explicitly selected externally recorded earlier tip. Follow the recovery-to-restore runbook to restore actual content using the recovered metadata and surviving mirror while the original primary and checkout remain unavailable.
6. Restore selected and broad snapshots into a clean temporary root and compare expected content, modes, mtimes, and symlinks.
7. Confirm the retained private key chain decrypts both pack and metadata-bundle fixtures.
8. Accept the exact production `backup-server` deployment as described above.
