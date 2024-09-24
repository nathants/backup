# backup

## why

backups should be simple and easy.

## how

easily create immutable, trustless backups with revision history, compression, and file deduplication.

## what

- the index, tracked in git, contains filesystem metadata.

- the [index](./examples/index) is a sorted tsv file of: `path, tarball, hash, size, mode`

- for every line of metadata in the index, there is one and only one tarball containing a file with that hash.

- duplicate files, by [blake2b](https://www.blake2.net/) hash, are never stored.

- the index is encrypted with [git-remote-aws](https://github.com/nathants/git-remote-aws).

- the tarballs are split into chunks, compressed with [lz4](https://github.com/lz4/lz4), then encrypted with [git-remote-aws](https://github.com/nathants/git-remote-aws).

- remote storage on [s3](https://aws.amazon.com/s3/) is handled via [libaws](https://github.com/nathants/libaws).

- the [ignore](./examples/ignore) file, tracked in git, contains one regex per line of file paths to ignore.

- a clean restore will clone the git repo, checkout a revision, select file paths by regex, gather needed tarball names, fetch tarballs from storage, and extract the selected files.

## usage

- `backup-add` - scan the filesystem for changes.
- `backup-diff` - inspect the uncommitted backup diff.
- `backup-ignore` - if needed, edit the ignore regexes, then goto `backup-add`.
- `backup-commit` - commit the backup diff to remote storage.
- `backup-find` - search for files in the index by regex at revision.
- `backup-restore` - restore files from remote storage by regex at revision.

## dependencies

- awk
- bash
- cat
- git
- git-remote-aws
- grep
- lz4
- python3
- libaws

## installation

- put `bin/` on `$PATH`

or

- `sudo mv bin/* /usr/local/bin`

## setup

- add some environment variables to your bashrc:

  `export BACKUP_ROOT=~` - root directory to backup

  `export BACKUP_S3=s3://${bucket-name}/${backup-name}` - s3 storage for the tarballs

  `export BACKUP_GIT=aws://${bucket-name}+git-remote-aws/${backup-name}` - git storage for the index

  `export BACKUP_CHUNK_MEGABYTES=100` - approximate size of each tarball before compression

## api

modify backup state:
- `backup-add` - scan the filesystem for changes
- `backup-commit` - commit the backup diff to remote storage
- `backup-ignore` - edit the ignore file in $EDITOR
- `backup-reset` - clear uncommited backup state

view backup state:
- `backup-additions-sizes` - show large files in the uncommited backup diff
- `backup-additions` - inspect the uncommited backup diff, additions only
- `backup-diff` - inspect the uncommited backup diff
- `backup-find` - find files by regex at revision
- `backup-index` - view the backup index
- `backup-log` - view the git log

restore backup content:
- `backup-restore` - restore files from remote storage by regex at revision

## test

```
export BACKUP_TEST_S3=s3://${bucket-name}/${backup-name}
export BACKUP_TEST_GIT=aws://${bucket-name}+git-remote-aws/${backup-name}
tox
```

## mirrors

to mirror tarballs to [r2](https://www.cloudflare.com/developer-platform/r2/) and/or local filesystem, define these optional env vars:
- `export BACKUP_FS=/mnt/${backup-name}`
- `export BACKUP_R2=s3://${bucket-name}/${backup-name}`

on backup, define up to all three.

on restore, define one, or they will be tried in this order:
- `fs`
- `r2`
- `s3`
