# Backup

## Why

Backups should be simple and easy.

## How

Easily create immutable, trustless backups with revision history, compression, and file deduplication.

## What

- The index, tracked in git, contains filesystem metadata.

- The [index](./examples/index) is a sorted TSV file of: `path, tarball, hash, size, mode`

- For every line of metadata in the index, there is one and only one tarball containing a file with that hash.

- Duplicate files, by [BLAKE2b](https://www.blake2.net/) hash, are never stored.

- The index is encrypted with [git-remote-aws](https://github.com/nathants/git-remote-aws).

- Chunked tarballs are compressed with [lz4](https://github.com/lz4/lz4) then encrypted with [git-remote-aws](https://github.com/nathants/git-remote-aws).

- Tarballs are stored on [S3](https://aws.amazon.com/s3/) and optionally [mirrored](#mirrors) to other remotes.

- The [ignore](./examples/ignore) file, tracked in git, contains one regex per line of file paths to ignore.

- A clean restore will clone the git repo, checkout a revision, select file paths by regex, gather needed tarball names, fetch tarballs from storage, and extract the selected files.

## Usage

- `backup-add` - Scan the filesystem for changes.
- `backup-diff` - Inspect the uncommitted backup diff.
- `backup-ignore` - If needed, edit the ignore regexes, then goto `backup-add`.
- `backup-commit` - Commit the backup diff to remote storage.
- `backup-find` - Search for files in the index by regex at revision.
- `backup-restore` - Restore files from remote storage by regex at revision.

## Dependencies

- awk
- aws
- bash
- cat
- git
- git-remote-aws
- grep
- lz4
- python3

## Installation

- Put `bin/` on `$PATH`

or

- `sudo mv bin/* /usr/local/bin`

## Setup

- Add some environment variables to your bashrc:

  `export BACKUP_ROOT=~` - Root directory to backup

  `export BACKUP_S3=s3://${bucket-name}/${backup-name}` - S3 storage for the tarballs

  `export BACKUP_GIT=aws://${bucket-name}+git-remote-aws/${backup-name}` - Git storage for the index

  `export BACKUP_CHUNK_MEGABYTES=100` - Approximate size of each tarball before compression

## API

Modify backup state:
- `backup-add` - Scan the filesystem for changes
- `backup-commit` - Commit the backup diff to remote storage
- `backup-ignore` - Edit the ignore file in $EDITOR
- `backup-reset` - Clear uncommited backup state

View backup state:
- `backup-additions-sizes` - Show large files in the uncommited backup diff
- `backup-additions` - Inspect the uncommited backup diff, additions only
- `backup-diff` - Inspect the uncommited backup diff
- `backup-find` - Find files by regex at revision
- `backup-index` - View the backup index
- `backup-log` - View the git log

Restore backup content:
- `backup-restore` - Restore files from remote storage by regex at revision

## Test

Tests require [libaws](https://github.com/nathants/libaws)

```
export BACKUP_TEST_S3=s3://${bucket-name}/${backup-name}
export BACKUP_TEST_GIT=aws://${bucket-name}+git-remote-aws/${backup-name}
tox
```

## Mirrors

To mirror tarballs to [R2](https://www.cloudflare.com/developer-platform/r2/) and/or local filesystem, define these optional env vars:
- `export BACKUP_FS=/mnt/${backup-name}`
- `export BACKUP_R2=s3://${bucket-name}/${backup-name}`

On backup, define up to all three.

On restore, define one, or they will be tried in this order:
- `fs`
- `r2`
- `s3`

To use R2, you must define these env vars:
- `R2_ACCESS_KEY_ID`
- `R2_ACCESS_KEY_SECRET`
- `R2_ACCOUNT_ID`
