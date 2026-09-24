# Backup

Encrypted, deduplicated Linux backups to append-only object storage. One Go binary
provides the client and a small S3-compatible server.

- Git stores readable snapshot metadata and history.
- Encrypted packs go to one or more mirrors: native filesystem storage, `backup server`,
  AWS S3, or Cloudflare R2.
- Each successful revision is complete on at least one individual mirror, including
  enough metadata to recover without the primary Git service.
- Restore verifies selected content before publishing files. Repair relocates healthy
  bytes to new immutable keys; it never overwrites old objects.

## Build

Requires Linux 5.8+, Go 1.27+, Git 2.36+ with SHA-256 support, and Libsodium headers.

```sh
make
# equivalently: make build
```

Metadata hosting uses [git-remote-aws](https://github.com/nathants/git-remote-aws).

## Prepare and back up

Initialization is local only. It neither contacts remotes nor publishes a revision.

```sh
./backup init --root /data
cat /private/keys/alice.public > /data/.backup/.publickeys
# Edit /data/.backup/ignore and configure /data/.backup-config.
./backup add --root /data
./backup diff --root /data
./backup commit --root /data
```

`add`, `replan`, `commit`, `verify`, `restore`, `sync`, `recover` (including
`--list`), and both `repair` commands report phases and available counters on stderr.
Long waits emit a roughly five-second heartbeat; "still running" is not evidence
of forward progress or durable completion. Progress is best-effort: a failed output
sink disables it without changing the operation's result. Errors writing mandatory
warnings or final results still fail the command. Stdout retains the command results.

Every command also records its stdout/stderr in private JSON Lines files under
`~/.backup-logs/`, labeled with time, run ID, command, and output stream.
Logs rotate daily; files last written more than 14 days ago are removed on the
next invocation or daily rollover. There is no byte cap. Disk-logging failures
warn on stderr without changing the command's result. Logs contain paths and
results, but no additional argument/environment dump; treat them as private
local diagnostics, not a durable audit trail.

`add` fixes the selected paths; `commit` captures their current content. Git ignore
rules apply even outside repositories. Incomplete Git metadata produces a warning
and pattern-only matching, without tracked-file exceptions. Non-ignored untracked
work is included. The backup ignore file contains Go regular expressions, not Git
patterns.

Source permission denials skip the affected file, symlink, or directory subtree
with a warning; broken and outside-root symlinks are also skipped. Review add's
warnings and skip counts before committing: omitted paths are absent from the new
snapshot. Permissions are never changed automatically. Ignore-policy, metadata,
and staging failures still stop the operation.

Configure the trusted remote and mirrors before the first commit. Fields below are
separated by literal tabs; credentials stay in local AWS shared-credential profiles.

```text
git-remote	aws://metadata-bucket+dynamodb-table/repository
branch	main
mirror	local	backup-server	s3://backup-bucket/repository	https://backup.example:8443	us-east-1	backup-profile	/etc/backup/ca.pem
```

For a native ext4 destination, follow [filesystem mirrors](docs/filesystem-mirrors.md)
for explicit `mirror-init`, store identity, mount binding, and configuration. It
needs no server or object-store credential; the Git primary is still mandatory.

Public recipient chains live in `.backup/.publickeys`. New encryption uses each
recipient's newest generation; retain historical private generations for old data.
See [key management](docs/key-management.md) for generation, rotation, and on-demand
secret loading. Storage credentials and encryption keys are separate.

## Verify and restore

```sh
export GIT_REMOTE_AWS_SECRETKEY_FILE=/private/keys/alice.secret
./backup verify --root /data --minimum-mirrors 1
./backup restore --root /data --target /safe/restore '^\./' HEAD
```

Protocol `verify` checks object availability, checksums, and declared metadata-chain
relationships without downloading encrypted bodies. It does not prove that an
unfamiliar historical bundle reconstructs its claimed Git revision. A false manifest
can mask a missing genuine edge in this audit, but cannot destroy an existing healthy
immutable chain. Retain external revision anchors and periodically exercise actual
metadata recovery, which decrypts/imports bundles and rejects false representations.

Native filesystem verification reads and hashes local ciphertext. `verify --full`
also decrypts and verifies every catalog pack and reconstructs the selected metadata
tip; it requires eligible secrets and counts only filesystem mirrors.

Pending publication is stricter: verification and finalization require the exact
metadata representation recorded in the transaction. `repair metadata` can validate,
publish, and atomically adopt a replacement for that pending edge. A completion-ledger
commit ID alone never authorizes discarding pending staging. No additional keys or
permanent local provenance database are needed for restore.

For loss of the primary metadata service, follow
[recovery and restore](docs/recovery-restore.md). Recovery reconstructs metadata;
restore reconstructs files.

## Boundaries

Each repository has one authoritative writer. Mirrors are append-only and grow
without garbage collection. Cloud deployments must pass their immutability contracts
before production use; successful uploads alone do not establish ransomware resistance.
Filesystem mirrors are an explicit exception: backup never replaces published objects,
but a compromised user with direct filesystem write access can overwrite or delete them.

This is a content archive, not a full system image: regular-file content, permissions,
modification times, and in-root symlink topology are preserved. Ownership, ACLs,
xattrs, special files, and empty directories are not.

Keep the restore destination exclusively controlled. Use operator-enforced resource
limits for potentially malicious backups, including metadata recovery and listing.

## Development

```sh
make check  # lint, coverage, race detector, vet
make fuzz
```

See [design and operations](docs/design.md) for the storage format, invariants, deployment
contracts, and production acceptance gates. The separate
[Git-primary contract](docs/git-primary-contract.md) tests helper interoperability.
