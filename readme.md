# Backup

Encrypted, deduplicated Linux backups to append-only object storage. One Go binary
provides the client and a small S3-compatible server.

- Git stores readable snapshot metadata and history.
- Encrypted packs go to one or more mirrors: `backup server`, AWS S3, or Cloudflare R2.
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

`add` fixes the selected paths; `commit` captures their current content. Git-ignored
files are skipped, but non-ignored untracked work is included. The backup ignore
file contains Go regular expressions, not Git patterns.

Configure the trusted remote and mirrors before the first commit. Fields below are
separated by literal tabs; credentials stay in local AWS shared-credential profiles.

```text
git-remote	aws://metadata-bucket+dynamodb-table/repository
branch	main
mirror	local	backup-server	s3://backup-bucket/repository	https://backup.example:8443	us-east-1	backup-profile	/etc/backup/ca.pem
```

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

For loss of the primary metadata service, follow
[recovery and restore](docs/recovery-restore.md). Recovery reconstructs metadata;
restore reconstructs files.

## Boundaries

Each repository has one authoritative writer. Mirrors are append-only and grow
without garbage collection. Cloud deployments must pass their immutability contracts
before production use; successful uploads alone do not establish ransomware resistance.

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

See [design and operations](NINA.md) for the storage format, invariants, deployment
contracts, and production acceptance gates. The separate
[Git-primary contract](docs/git-primary-contract.md) tests helper interoperability.
