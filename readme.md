# backup

## why

backups should be simple and easy.

## how

easily create immutable, trustless backups with revision history, compression, and file deduplication.

## what

- the index, tracked in git, contains filesystem metadata.

- the [index](./examples/index) is a sorted tsv file of: `path, tarball, hash, size`

- for every line of metadata in the index, there is one and only one tarball containing a file with that hash.

- duplicate files, by [blake2b](https://www.blake2.net/) hash, are never stored.

- the index is encrypted with [git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt).

- the tarballs are split into chunks, compressed with [lz4](https://github.com/lz4/lz4), then encrypted with [gpg](https://gnupg.org/).

- all remote storage is handled via [rclone](https://rclone.org/) on any [backend](https://rclone.org/overview/#features) it supports.

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
- git-remote-gcrypt
- gpg
- grep
- lz4
- python3
- rclone

## installation

- put `bin/` on `$PATH`

or

- `sudo mv bin/* /usr/local/bin`

## setup

- add some environment variables to your bashrc:

  `export BACKUP_ROOT=~` - root directory to backup

  `export BACKUP_RCLONE_REMOTE=$REMOTE` - a remote setup with `rclone config`

  `export BACKUP_DESTINATION=$BUCKET/backups/$(hostname)` - where to rclone data to

  `export BACKUP_CHUNK_MEGABYTES=100` - approximate size of each tarball before compression

- have a gpg key and a gpg.conf that looks like the following:

  ```
  >> cat ~/.gnupg/gpg.conf

  default-key YOUR@EMAIL.COM
  default-recipient YOUR@EMAIL.COM

  personal-cipher-preferences AES256
  personal-digest-preferences SHA512
  personal-compress-preferences Uncompressed
  default-preference-list SHA512 AES256 Uncompressed
  cert-digest-algo SHA512
  s2k-cipher-algo AES256
  s2k-digest-algo SHA512
  s2k-mode 3
  s2k-count 65011712
  disable-cipher-algo 3DES
  weak-digest SHA1
  force-mdc
  ```

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
export BACKUP_TEST_RCLONE_REMOTE=$REMOTE
export BACKUP_TEST_DESTINATION=$BUCKET/test
tox
```
