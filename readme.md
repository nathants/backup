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
make check                # cloud-free coverage, race detector, and vet
make fuzz                 # ten seconds per parser/path/tar target
make fuzz FUZZ_TIME=1m    # longer pre-release campaign
```

`make check` is deterministic and cloud-free. It covers the local filesystem and in-process server paths but does not require Docker, AWS, or R2. Fuzz seed corpora run during ordinary `go test`; `make fuzz` performs mutation campaigns against the actual canonical parsers, path/key grammars, local configuration parser, tar reader, and SigV4 request-target/query parsing.

## AWS infrastructure

[`infra.yaml`](infra.yaml) declares one dedicated private, versioned, append-only AWS bucket and separate create-only writer and read/list-only auditor users. Libaws converges TLS-only access, default SSE-S3 `AES256`, blocked SSE-C, conditional object creation, and denied object/version deletion. Backup still explicitly requests and verifies `AES256` for every AWS object. Infrastructure ensure never creates credentials.

```sh
export BACKUP_AWS_INFRASET=backup-production
export BACKUP_AWS_BUCKET=globally-unique-backup-bucket
export BACKUP_AWS_WRITER_USER=backup-production-writer
export BACKUP_AWS_READER_USER=backup-production-reader

libaws infra-ensure ./infra.yaml --preview
libaws infra-ensure ./infra.yaml

# Each command prints a secret only when it creates the user's sole key.
libaws iam-ensure-user-api-key "$BACKUP_AWS_WRITER_USER"
libaws iam-ensure-user-api-key "$BACKUP_AWS_READER_USER"
```

Store those one-time secrets in the distinct trusted writer and reader profiles used by `.backup-config`. Removing this infrastructure is deliberately destructive: `libaws infra-rm ./infra.yaml` revokes both users and deletes every bucket object and version.

## Integration

`make integration` first runs the complete cloud-free `make check`, then runs one real-backend suite against the non-root Docker server and an ephemeral AWS deployment by default. It validates the Docker daemon and explicit AWS account guard, completes a bounded observable Docker build before creating AWS resources, instantiates unique infrastructure from the production `infra.yaml`, bootstraps distinct ordinary writer and reader keys, runs the integration package normally and under the race detector, and removes the users, every object version, and the bucket once on every exit. The test processes receive only the generated ordinary credentials, not the administrator credentials used for setup and teardown.

```sh
# Requires Docker, administrator AWS credentials, a region, and this guard.
export LIBAWS_TEST_ACCOUNT=123456789012
make integration
# Set LIBAWS=/path/to/libaws when the reviewed binary is not on PATH.
```

The AWS run proves provisioning and enforcement but deliberately retains no production data. R2 joins the same suite only when explicitly enabled because its security boundary is Cloudflare Bucket Lock rather than libaws bucket-policy provisioning:

```sh
# Set BACKUP_R2_CONTRACT_{BUCKET,REGION,WRITER_ACCESS_KEY,
# WRITER_SECRET_KEY,READER_ACCESS_KEY,READER_SECRET_KEY,ENDPOINT,ACCOUNT_ID,
# LOCK_AUDIT_TOKEN}; PREFIX and JURISDICTION are optional. Run this only after
# an indefinite Cloudflare bucket-lock rule protects the entire test prefix.
BACKUP_R2_CONTRACT=1 make integration
```

The contracts deliberately attempt unconditional/copy/multipart overwrites, ordinary and version-specific delete and batch-delete, role escalation, wrong checksums, SSE-C, and bucket-policy/public-access/encryption/lifecycle/immutability/versioning control-plane changes. They also prove AWS applies default SSE-S3 when a request omits an encryption header. The R2 contract reads the native Bucket Lock API, requires an enabled indefinite rule covering the exact test namespace, and proves both ordinary S3 credential values cannot reach that API. R2 successful probes are intentionally never deleted.

### Exact production AWS acceptance

The disposable AWS deployment above validates `infra.yaml`, but it does not accept an already configured production bucket. Before storing the first production backup, run the AWS contract directly against that exact bucket with its distinct ordinary writer and reader credentials—never administrator credentials. The test uses fresh random object keys, but deliberately submits destructive and bucket-wide control-plane requests that must be denied; first inspect the deployed policy and run this before the bucket contains production data.

```bash
set -euo pipefail

export BACKUP_AWS_CONTRACT=1
export BACKUP_AWS_CONTRACT_BUCKET=globally-unique-production-bucket
export BACKUP_AWS_CONTRACT_REGION=ap-northeast-1
export BACKUP_AWS_CONTRACT_PREFIX='' # or the exact configured production prefix
export BACKUP_AWS_CONTRACT_WRITER_ACCESS_KEY=...
export BACKUP_AWS_CONTRACT_WRITER_SECRET_KEY=...
export BACKUP_AWS_CONTRACT_READER_ACCESS_KEY=...
export BACKUP_AWS_CONTRACT_READER_SECRET_KEY=...
unset BACKUP_AWS_CONTRACT_WRITER_SESSION_TOKEN BACKUP_AWS_CONTRACT_READER_SESSION_TOKEN
# Export the corresponding *_SESSION_TOKEN values after this when credentials are temporary.
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

A passing run repeatedly checksum-audits the immutable probe after the denied attacks and prints its exact `s3://` URI, plus the default-encryption probe URI. The direct test does not remove either object. Preserve the private log and externally record the passing run and immutable-probe URI as production acceptance evidence.

The Docker portion of `make integration` is the remote `backup-server` software contract: clients access the real production binary over verified TLS, and the suite restarts it against the same persistent volume. This accepts the backend implementation, not an already deployed instance. For that exact deployment, confirm its TLS endpoint and distinct ordinary writer/reader credentials, then restart it against the same data directory and repeat verification and restore; no duplicate destructive contract suite is required.
