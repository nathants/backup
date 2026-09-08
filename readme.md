# backup

`backup` creates append-only, recipient-encrypted filesystem backups with Git-versioned metadata and independently recoverable S3-compatible object mirrors.

The authoritative format, threat model, and invariants are documented in [`NINA.md`](NINA.md).

## Build

```sh
go build ./cmd/backup
```

Linux, Git with SHA-256 support, and libsodium are required. Production metadata hosting uses `git-remote-aws`.

## Trusted local configuration

By default the client reads `$BACKUP_ROOT/.backup-config` (`BACKUP_ROOT` defaults to `/`). The file must be regular, bounded, and not group/other writable. It is raw tab/LF text:

```text
git-remote	aws://metadata-bucket+dynamodb-table/repository
branch	main
mirror	local	backup-server	s3://backup-bucket/repository	https://backup.example:8443	us-east-1	writer-profile	reader-profile	/etc/backup/ca.pem
```

Each mirror row is:

```text
mirror  name  kind  s3_url  endpoint  region  writer_profile  reader_profile  ca_file
```

Use `-` for a provider-default endpoint, absent role profile, or system trust roots. Mirror identity is pinned both here and in canonical `mirrors.tsv`; disagreement fails before network access.

## Initialize

Generate and independently store a permanent recovery keypair with `git-remote-aws --keygen`, then initialize with its public key:

```sh
backup init --root /data --recovery-public-key "$GIT_REMOTE_AWS_PUBLICKEY"
```

`init` publishes one SHA-256 Git genesis commit and completes a full encrypted metadata bundle on at least one mirror before success.

## Backup

```sh
backup add --root /data
backup diff --root /data
backup commit --root /data
```

`add` always reads every included regular file and stages the exact reviewed path set plus provisional metadata; repeated `add` replaces that plan. `commit` never discovers post-add paths. It captures each planned path's current bytes and metadata, warns about changes/removals since `add`, privately spools at most one complete file, and records a pack only after one individual mirror has all of its parts. A trusted alternate plaintext-spool parent can be selected with `--spool-directory`; `--space-reserve-bytes` sets retained free-space headroom. `commit` is resumable at completed-pack boundaries and reports the exact Git SHA-256 commit and complete/lagging mirrors.

## Restore and verify

```sh
export BACKUP_SECRET_KEY=...
backup verify --root /data --minimum-mirrors 1
backup restore --root /data --target /safe/restore '^\./home/' HEAD
```

Restore verifies all selected ciphertext, encryption authentication, archive structure, and plaintext hashes before publishing any selected path. Existing leaves require `--overwrite`. Historical repair relocation is explicit with `--catalog-revision`.

## Recovery, sync, and repair

```sh
backup recover --root /data --mirror local --list
backup recover --root /data --mirror local --tip COMMIT --destination /safe/recovered.git
backup sync --root /data --source local --destination aws
backup repair data --root /data --source aws PACK_HASH PART_NUMBER
backup repair metadata --root /data --destination local --revision COMMIT
```

Recovery uses only one object mirror plus the recipient secret key; the primary Git remote need not be available. Data repair publishes healthy ciphertext under a fresh immutable key and commits only the `object_id` relocation. Metadata repair rebuilds and validates the exact Git edge, then publishes a fresh encrypted representation without changing Git history; it also requires the recipient secret key for end-to-end validation.

## Production server

The server requires supplied TLS material and separate writer/reader credentials:

```sh
export BACKUP_SERVER_WRITER_ACCESS_KEY=...
export BACKUP_SERVER_WRITER_SECRET_KEY=...
export BACKUP_SERVER_READER_ACCESS_KEY=...
export BACKUP_SERVER_READER_SECRET_KEY=...
backup server \
  --listen :8443 \
  --data-root /var/lib/backup \
  --bucket backup \
  --prefix repository \
  --region us-east-1 \
  --tls-cert /etc/backup/tls.crt \
  --tls-key /etc/backup/tls.key
```

The server supports only signed fixed-payload create-only PUT, reader GET/HEAD, and bounded ListObjectsV2. It has no delete, overwrite, multipart, copy, presigned, unsigned-payload, or streaming-payload API.

## Check

```sh
make check
make fuzz                 # ten seconds per parser/path/tar target
make fuzz FUZZ_TIME=1m    # longer pre-release campaign
make docker-test          # real non-root server containers and real client
```

Docker integration tests require Docker and run the real server image as non-root while the test client runs outside the container. Fuzz seed corpora also run during ordinary `go test`; `make fuzz` performs mutation campaigns against the actual canonical parsers, path/key grammars, local configuration parser, tar reader, and SigV4 request-target/query parsing.

Credential-gated cloud contracts use dedicated ordinary writer and reader credentials and retain immutable probes:

```sh
# Set BACKUP_AWS_CONTRACT_{BUCKET,REGION,WRITER_ACCESS_KEY,
# WRITER_SECRET_KEY,READER_ACCESS_KEY,READER_SECRET_KEY}; PREFIX is optional.
make aws-contract

# Set the analogous BACKUP_R2_CONTRACT_* variables plus ENDPOINT, ACCOUNT_ID,
# and LOCK_AUDIT_TOKEN (a separate Workers R2 Storage Read bearer token) only
# after an indefinite Cloudflare bucket-lock rule protects the entire test
# prefix. JURISDICTION is optional: default, eu, or fedramp.
make r2-contract
```

The contracts deliberately attempt unconditional/copy/multipart overwrites, ordinary and version-specific delete and batch-delete, role escalation, wrong checksums, disallowed AWS encryption modes, and bucket-policy/public-access/encryption/lifecycle/immutability/versioning control-plane changes. The R2 contract reads the native Bucket Lock API, requires an enabled indefinite rule covering the exact test namespace, and proves both ordinary S3 credential values cannot reach that API. Use dedicated buckets or prefixes; successful probes are intentionally never deleted.
