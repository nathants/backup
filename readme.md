# immutable backups so simple that unborkable

## what, why, how

simple, immutable, trustless, append only backups with full history and file level deduplication.

## installation

- works on linux, should work on mac with possible minor tweaks

- depends on:
  - awscli
  - bash
  - cut
  - git
  - git-remote-gcrypt
  - gpg
  - grep
  - lz4
  - pv
  - python3
  - scp
  - sort
  - ssh
  - tar
  - tee

- put `bin/` on `$PATH`

## setup

- add some required env vars:

`export BACKUP_AWS_ID=...`
`export BACKUP_AWS_KEY=...`
`export BACKUP_CHUNK_MEGABYTES=100`
`export BACKUP_HOST=my.remote.ssh.server`
`export BACKUP_MIRROR_S3="s3://bucket1/backup-$BACKUP_NAME s3://bucket2/backup-$BACKUP_NAME"`
`export BACKUP_MIRROR_S3_ARGS="--storage-class STANDARD_IA"`
`export BACKUP_NAME=$(hostname|cut -d- -f2)`
`export BACKUP_PATH=/mnt/backup-$BACKUP_NAME`
`export BACKUP_ROOT=~`


## api

`backup-add`

`backup-commit`

`backup-diff`

`backup-diff-sizes`

`backup-find`

`backup-log`

`backup-mirror`

`backup-reset`

`backup-restore`

`backup-verify`
