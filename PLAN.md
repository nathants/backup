# PLAN (Go rewrite)

## Goal

Rebuild this project in Go with:
- an **append-only, immutable** backup system (reads are OK; previously written data must not be mutable/deletable)
- a **single `backup` binary** with subcommands (use `go-args`)
- **local-only tests** that require no cloud resources
  - object storage is provided by a **local HTTPS server** with self-signed certs
  - metadata git remote is a **filesystem bare git repo** in tests

The existing design (git-tracked index + content-addressed dedup + packed blob uploads) is good and should remain conceptually.

This plan assumes a **clean break**: new metadata/pack formats are allowed.

### Decisions already made (so we can stop bikeshedding)

- **Single writer**. A second writer racing will fail to push; first writer wins.
- **Symlinks match current behavior**:
  - index stores a **canonical root-relative realpath target** (not the original link text)
  - restore recreates the link using `relpath(target, dirname(link))` so it resolves to the same file
  - broken links are skipped; links resolving outside `$BACKUP_ROOT` are skipped
- **Crypto scheme**: git-remote-aws compatible (libsodium secretstream + recipients / `.publickeys` model).
- **Pack naming**: keep the current “commit_number.timestamp + chunk suffix” style (human readable, monotonic-ish).
- **Object storage**: everything is S3-compatible (AWS S3, R2, local `backup server`). No BACKUP_FS-style mirroring.
- **Backup does not verify uploads** (no list/head/get during `backup commit`). Restore verifies via hashes in metadata.
- **Backup server SigV4 scope**:
  - **Authorization header only** (no presigned `X-Amz-*` query auth)
  - **path-style only** (`/{bucket}/{key...}`), and require `UsePathStyle=true` in clients
  - **streaming SigV4 supported** (`Content-Encoding: aws-chunked`), including trailers:
    - `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
    - `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` + `x-amz-trailer` + `x-amz-trailer-signature`
  - **no unsigned payloads** (reject `UNSIGNED-PAYLOAD` and `STREAMING-UNSIGNED-PAYLOAD-TRAILER`)

---

## High-level architecture

### Two stores

1) **Metadata store (git)**
- A git repo containing plaintext metadata files (index, ignore, object map, public keys).
- Remote can be:
  - `file://` (tests)
  - `aws://...` via **git-remote-aws** (recommended for encrypted git hosting)
  - any other git remote the user wants

2) **Object store (S3 API)**
- All backup blobs are stored via the **AWS SDK v2 S3 client**.
- Backends:
  - **AWS S3**
  - **R2** (as an S3-compatible endpoint)
  - **local `backup server`** implementing a subset of S3 over HTTPS (tests; also useful in production)

### Append-only / immutability model

- **Objects (packs)** are write-once: once a key exists, it must not be possible to overwrite or delete it.
- **Metadata history** must be append-only in the Git sense:
  - HEAD advances
  - old commits remain reachable
  - force-push / history rewrite should be prevented by the chosen remote (or by governance/policy)

---

## File formats (new)

All files live inside `$BACKUP_ROOT/.backup/` which is a git repo.

### 1) `index.tsv` (snapshot-by-path)
A sorted TSV, one line per tracked path (sorted lexicographically by `path`).

Columns:
1. `path`        - normalized, always starts with `./`
2. `kind`        - `file` | `symlink`
3. `ref`         - for `file`: `blake2b:<hex>`; for `symlink`: `target:<./root/relative/realpath>`
4. `size`        - bytes, `0` for symlink
5. `mode`        - `644` / `755` etc; `-` for symlink

Rationale:
- explicit `kind` and `ref` makes debugging simpler than overloading the “tarball” column
- still a single human-readable, grep-able file

### 2) `objects.tsv` (dedup map)
A mapping from content hash to where that content lives in object storage.

Columns:
1. `blake2b`      - hex
2. `pack_key`     - string key in object store

Rules:
- each `blake2b` must appear exactly once
- the mapping for a given `blake2b` must never change across history

#### Future: random access vs “mapping must never change” (why offsets are tricky)

If we ever want random-access restore without scanning tar streams, we’d want something like:

```
blake2b=<hash>  pack_key=<pack>  pack_offset=<bytes>  pack_length=<bytes>
```

But if we adopt the hard rule “a row for a given hash must never change across history”, then *backfilling* offsets later becomes impossible without violating that rule.

Examples:

- **v1 today**: `objects.tsv` has only `blake2b → pack_key`. Works fine, but restores must scan the tar to find the entry.
- **v2 later**: we want to add offsets for performance.
  - If we modify existing rows to fill `pack_offset/pack_length`, then the mapping for that `blake2b` changed across history (breaks the immutability invariant).

Recommendation:
- Keep v1 `objects.tsv` as **two columns only** (`blake2b`, `pack_key`).
- If/when we need random access, introduce a **new append-only artifact** rather than rewriting old rows, e.g.:
  - `packindex.tsv`: `pack_key`, `member_name`, `offset`, `length`, and keep `objects.tsv` unchanged, OR
  - `objects.v2.tsv` as a new file format/version.

### 3) `packs.tsv` (pack integrity)
Tracks pack object integrity for restores/auditing.

Columns:
1. `pack_key`
2. `cipher_blake2b`  - blake2b of the encrypted+compressed bytes
3. `cipher_size`
4. `created_utc`

### 4) `ignore` (regex, one per line)
Same idea as today.

### 5) `.publickeys`
Required. We keep git-remote-aws `.publickeys` semantics for operator familiarity and tooling reuse.

### Path normalization + TSV encoding rules (make this explicit)

Current system behavior (important to match where it matters):
- paths are root-relative and stored with a `./` prefix (from `os.walk('.')`)
- files are tab-separated in the index file
- many ancillary tools/tests accidentally parse output by **whitespace**, so paths-with-spaces are effectively unsupported today

New Go behavior (proposal / recommendation):
- the on-disk format is **TSV** and must be parsed as TSV (split on `\t`, not whitespace), so **paths with spaces are supported**
- we **forbid** `NUL`, `\n`, `\r`, `\t` in tracked paths and symlink targets (fatal error with a clear message)
- all stored paths are normalized:
  - always start with `./`
  - never contain `..` segments
  - use `/` separators in the TSV (even if running on a platform with different separators)

---

## Crypto / compression

### Compression
- Switch from lz4 to **zstd** (pure Go libs, widely used).
- Keep this as an implementation detail behind an interface.

### Encryption
**Reuse git-remote-aws scheme (required).**

- libsodium secretstream
- recipients are libsodium box keypairs
- `.publickeys` in the metadata repo controls who can decrypt
- secret key material comes from the same place git-remote-aws expects (or a compatible `*_CMD` style).

Store `cipher_blake2b` in `packs.tsv` to detect corruption/tampering.

---

## CLI (single binary)

`backup` (via go-args)

### Core subcommands

1. `backup init`
- create `$BACKUP_ROOT/.backup` git repo if missing
- write defaults: `ignore`, empty `index.tsv`, empty `objects.tsv`, empty `packs.tsv`
- add remote `origin` from env

2. `backup add`
- scan filesystem under `$BACKUP_ROOT`
- apply ignore regexes
- build new `index.tsv`
- compute blake2b for regular files
- apply symlink rules exactly like current:
  - skip broken links
  - only allow links that resolve inside `$BACKUP_ROOT`
  - store canonical root-relative realpath
- determine which hashes are new by consulting `objects.tsv`
- create one or more **pack files** containing only new hashes
- write a local **staging manifest** (untracked) describing:
  - which packs were created
  - which hashes are inside which pack
  - `cipher_blake2b` and `cipher_size` for each staged pack
  - (optional) the list of `index.tsv` changes for debugging
- stage metadata changes in git (`git add index.tsv`, etc)

3. `backup diff`
- show staged vs HEAD changes (similar to current UX)

4. `backup commit`
- upload newly created packs to object store (S3 API)
- append pack rows to `packs.tsv`
- append new object rows to `objects.tsv`
- commit metadata changes in git
- push to remote
- delete staged pack files + staging manifest after success

5. `backup find REGEX [REV]`
- read `index.tsv` at git revision
- print matching rows

6. `backup restore REGEX [REV]`
- default: overwrite existing files
- `--dry-run`: print what would be written and whether it’s new vs overwrite
- fetch required packs
- decrypt+decompress
- extract required hashes and write files
- restore symlinks

7. `backup reset`
- clear uncommitted state (like current `backup-reset`):
  - reset git working tree/index in `$BACKUP_ROOT/.backup` back to HEAD
  - delete any staged pack files + staging manifest

### Server subcommand (for tests; also useful in prod)

8. `backup server`
- production-grade **local S3-compatible HTTPS server** for packs
- implements a minimal surface:
  - `PutObject`, `GetObject`, `HeadObject` (optionally `ListObjectsV2`)
- **AWS SigV4 required** (normal `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` style credentials)
  - Authorization header only
  - path-style only
  - streaming SigV4 supported (including `...-PAYLOAD-TRAILER`)
  - reject unsigned payload modes: `UNSIGNED-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
- store objects on local disk
- enforce immutability:
  - reject PUT if key already exists
  - reject DELETE always
- provide self-signed cert generation (or accept user-provided cert/key)

---

## Object storage protocol details (S3 compatibility)

Because we want the **AWS SDK v2** client everywhere, the local server must be compatible enough.

Client-side requirements:
- configure S3 client with:
  - custom endpoint URL
  - `UsePathStyle=true`
  - custom TLS root (or insecure-skip-verify only in tests)
  - **force signed payloads**: aws-sdk-go-v2 defaults to `UNSIGNED-PAYLOAD` over HTTPS for S3, but our server rejects unsigned payloads.
    - plan: precompute SHA256 for the request body and set it via `aws/signer/v4` context (`v4.SetPayloadHash(ctx, hexSHA256)`), or equivalent middleware override.
  - **disable aws-sdk-go-v2 default request checksums/trailers** (otherwise the SDK can send `aws-chunked` + `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, which our server rejects)
    - set `cfg.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired`
    - do not set `ChecksumAlgorithm`

Server minimal behavior for AWS SDK compatibility:
- respond to:
  - `PUT /{bucket}/{key...}`
  - `GET /{bucket}/{key...}`
  - `HEAD /{bucket}/{key...}`
- **verify AWS SigV4** for the `s3` service, with this explicit scope:
  - Authorization header only (no presigned URLs)
  - path-style only
  - payload must be signed (reject `UNSIGNED-PAYLOAD` and `STREAMING-UNSIGNED-PAYLOAD-TRAILER`)
  - support streaming SigV4 (`Content-Encoding: aws-chunked`), including trailers:
    - require `x-amz-decoded-content-length`
    - `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
    - `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` + `x-amz-trailer` + `x-amz-trailer-signature`
- return basic S3-ish headers (`ETag`, `Content-Length`)
- return S3-style XML errors (enough for AWS SDK to surface useful messages)

Prior art (Go) for SigV4 verification (reference only; implement bespoke):
- `rclone/gofakes3` signature verifier (`signature/signature-v4*.go`) (small, server-side)
- `seaweedfs/seaweedfs` S3 gateway auth code (Apache-2.0)
- `minio/minio` SigV4 verifier is very complete but is **AGPL** (good for understanding edge cases, not for copying)
- `LeeDigitalWorks/zapfs/pkg/s3api/signature` (streaming chunk reader verification; good reference for `aws-chunked`)
- AWS docs: `sigv4-streaming.html` and `sigv4-streaming-trailers.html` (wire format + trailer signature rules)
- `aws-sdk-go-v2/service/internal/checksum/aws_chunked_encoding.go` (aws-chunked framing reference; note: this code implements the **unsigned trailer** variant)

---

## Immutability enforcement (real S3)

We want the remote to actively prevent mutation/deletion.

Recommended deployment model:
1) Clients upload packs either:
   - directly to an S3 bucket configured for immutability, or
   - to a **backup server** which enforces immutability and writes to S3 with a restricted IAM role

2) On S3:
- deny `s3:DeleteObject`
- ensure overwrites are impossible (either by policy conventions + monitoring, or by object-lock + pinning)

Notes / decisions:
- The **backup client does not run verification** (`ListObjects`, `HeadObject`, `GetObject`) during commit.
  - This enables a write-only backup credential for the pack store.
- The **backup server** is the primary append-only enforcement point.
- We do **not** record object VersionIds; we rely on correct bucket/server configuration.

---

## Git remote immutability (git-remote-aws)

Findings from reading `/home/nathants/repos/git-remote-aws`:
- It prevents force-push at the git protocol level (requires local contains remote head).
- It stores bundles as immutable S3 objects (unique keys by commit hash ranges).
- It currently **deletes old bundle-list objects** (`DeleteObject(oldBundlesS3Key)`), which conflicts with strict “no delete” buckets.

Plan options:
1) Patch git-remote-aws to never delete old bundle metadata objects.
2) Use a dedicated git hosting setup with server-side protections.
3) Accept that the git-remote-aws bucket cannot be fully delete-protected (not recommended if we want strong immutability for metadata).

---

## Implementation phases

### Phase 1: Skeleton + formats
- Create Go module
- Implement config-from-env parsing
- Implement parsing/writing for `index.tsv`, `objects.tsv`, `packs.tsv`
- Implement path normalization + safety checks

### Phase 2: Scanner
- Walk filesystem (`filepath.WalkDir`)
- Apply ignore regex
- Hash files streaming (blake2b)
- Capture mode
- Implement symlink rules

### Phase 3: Pack writer
- Chunking by approximate size (`BACKUP_CHUNK_MEGABYTES`)
- Create `tar` with entries named by blake2b
- Compress + encrypt streaming
- Produce `cipher_blake2b` + `cipher_size`

### Phase 4: Object store client
- AWS SDK v2 S3 client wrapper
- `PutObject` (commit) and `GetObject` (restore) operations
- `HeadObject` / listing are not used by `backup commit` (write-only backup credentials are supported)

### Phase 5: Metadata git plumbing
- Use `git` CLI (keep simple): init, add, commit, push, show
- Ensure atomic file writes (temp + rename)
- Local lock file to prevent concurrent operations

### Phase 6: Restore
- Find matching paths at revision
- Determine required hashes => pack keys via `objects.tsv`
- Download packs, verify `cipher_blake2b`, decrypt/decompress, extract
- Write files (overwrite by default), chmod, symlinks
- `--dry-run` output: new vs overwrite

### Phase 7: Local server
- Implement minimal S3-ish HTTPS server
- Disk backend
- Immutability enforcement
- Test helper to start server with generated cert
- Keep the server implementation in a clearly isolatable package (minimal deps, no backup-specific logic) so we can extract it later.
- SigV4 verification:
  - Authorization header only
  - path-style only
  - streaming SigV4 supported (`aws-chunked`), including `...-PAYLOAD-TRAILER`
  - reject unsigned payload modes: `UNSIGNED-PAYLOAD`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`

### Phase 8: Tests (local-only)
- All tests use temp dirs
- Local bare git remote (`git init --bare`)
- Spawn `backup server` on random port
- Configure client to use server endpoint
- Test scenarios:
  - basic add/commit/restore
  - multi-pack chunking (set chunk size tiny)
  - symlink cases
  - immutability: PUT same key twice should fail
  - restore `--dry-run` correctness
  - server auth:
    - accept SigV4 header auth with signed payload hash (no `UNSIGNED-PAYLOAD`)
    - reject `UNSIGNED-PAYLOAD`
    - reject `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
    - accept SigV4 streaming payload (`aws-chunked`, `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) via a purpose-built test request generator
    - accept SigV4 streaming payload with trailer (`aws-chunked`, `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`, `x-amz-trailer`, `x-amz-trailer-signature`) via a purpose-built test request generator

Test invocation style:
- `go test ./... -o /tmp/backup.test -c && /tmp/backup.test -test.v -test.count=1`

--- 

## Environment variables (proposed)

Keep env-based UX.

Required:
- `BACKUP_ROOT`
- `BACKUP_GIT`               - git remote URL for metadata
- `BACKUP_S3`                - `s3://bucket/prefix` for packs

Optional:
- `BACKUP_CHUNK_MEGABYTES`   - default 100
- `BACKUP_S3_ENDPOINT`       - override endpoint for local server/R2
- `BACKUP_S3_REGION`         - default `us-east-1`
- `BACKUP_S3_INSECURE_TLS`   - for local tests only
- encryption env vars: git-remote-aws compatible (TBD exact names; keep `.publickeys` semantics)

---

## Remaining open issues (but not blockers to start coding)

1) `git-remote-aws` metadata immutability: it currently deletes old bundle-list objects, which conflicts with strict “no deletes ever” buckets.
   - likely fix: patch it to never delete, only append.
