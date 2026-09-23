# Recipient chains and rotation

Backup and git-remote-aws use the same go-libsodium key-chain parser, crypto_box
key generation, recipient-stream encryption, and on-demand secret loader. There
is no distinguished recovery recipient, signing key, offline-key option, or
exceptional decryption path. An ordinary recipient may be held offline by choice.
A recipient grants decryption capability, not Git or object-store write permission.

## Files and syntax

`$BACKUP_ROOT/.backup/.publickeys` is the tracked public recipient list.
`backup init` creates it empty. Local add/replan/diff/reset work without keys;
commit requires at least one recipient before binding/publishing the remote.
Recipient edits after add require another add. Only ignore edits can use replan.

Each line belongs to one individual. Each generation is exactly 64 lowercase hex
characters (the existing 32-byte libsodium box key); generations are joined with
colons, oldest first. Recipient rows form an unordered set: their order has no
policy meaning and is preserved when serializing. Blank lines are ignored and
the final LF is optional. No spaces, tabs, CR, comments, or duplicate key values
are accepted. A single existing key is a one-generation chain. Public and private
chains use the same syntax but are kept in separate files; never commit secrets.
Secret rows need not correspond to every public recipient: each user normally
supplies only their own private chain.

Limits are shared: 1,024 generations per individual and 65,536 keys in total, with a
4,259,840-byte input ceiling. Secret files must be bounded regular files, not
symlinks, and allow only owner read/write permissions (no execute or special bits).
Public personal files may be readable by others but must not be group/other writable.

New encryption targets only the final public generation of each recipient.
Regenerating a historical metadata bundle uses today's validated HEAD recipients;
copying existing ciphertext during sync/data repair preserves its original keys.
Decryption selects any matching retained secret using the fingerprint already
present in the ciphertext header; it does not retry or buffer the encrypted body
for each generation. Missing keys are fatal when required content cannot be
opened, not merely because another recipient's secrets are absent. A complete
historical restore may require all generations of your private chain.

Retained public chains may only extend on the right. Entire recipients may be
added or removed, with at least one left for publication. These are structural
transition checks, not cryptographic proof of succession: there are no rotation
signatures, identity certificates, or trusted key registry. Keep trusted metadata
anchors and review recipient changes. Rotating keys cannot revoke previously
obtained ciphertext, and adding recipients does not by itself unlock existing ciphertext.
Storage-credential revocation is separate and cannot revoke downloaded bytes.

## Generate or rotate your personal files

Use git-remote-aws, not a backup-specific key generator:

```sh
git-remote-aws --keygen \
  --public-key-file /private/keys/alice.public \
  --secret-key-file /private/keys/alice.secret
```

Both explicit path flags must be nonempty; empty flags never fall back to stdout key
generation. Both paths must be absent (create a pair) or both must contain exactly
one matching personal chain (append a generation). Every existing public/private
generation is checked before writing. Keygen does not automatically discover or
update repository recipient lists: pass only your personal file pair, not a
repository's `.publickeys`. Copy the public chain into each intended repository's
`.publickeys`, preserving its other recipients. Generated personal files have one
LF-terminated row. Repository edits, including row reordering or blank-line changes,
must be committed before a helper push; unrelated worktree edits are allowed.

The private extension is fsynced/published before the public extension. Both
files are individually atomic, not a two-file transaction. If interrupted, retain
both files and inspect their generation counts before retrying. A one-generation
private lead can be reconciled by deriving its public generation using
`libsodium.BoxPublicKey`, verifying the preceding pairs, and explicitly extending
the public file. Never discard the new private generation or blindly generate
another pair to hide a mismatch. The operator must exclusively control the key
files and their ancestors; directory flocks serialize cooperating keygen calls.
There is no secure-deletion guarantee for replaced files or in-memory secrets.

Without file arguments, `git-remote-aws --keygen` still emits a fresh pair as
`GIT_REMOTE_AWS_PUBLICKEY`/`GIT_REMOTE_AWS_SECRETKEY` export statements. For
secret-manager/env-based storage, append each new generation yourself to both
chains, save the private extension first, and only then activate the public one.
Do not print real keygen output into retained logs or shell history.

## Load secrets on demand

Configure exactly one nonempty source in **both** programs:

1. `GIT_REMOTE_AWS_SECRETKEY`: chain text directly.
2. `GIT_REMOTE_AWS_SECRETKEY_FILE`: a private chain file.
3. `GIT_REMOTE_AWS_SECRETKEY_CMD`: an executable which prints chain text to stdout.

Environment values and command output may omit the final LF. The command is not shell
syntax. It receives the metadata remote URL as one argument when available;
standalone `--decrypt` supplies no argument. A wrapper can call your secret manager
and pinentry, but must not echo secrets to stderr or logs. Captured command output is
bounded, and failure never falls back to another source. Cancellation or oversized
output terminates the command process group; inherited output pipes have a 250ms
post-exit drain limit. There is no overall pinentry deadline, and this is not
containment of deliberately escaped jobs. One helper fetch/backup decryption
operation reuses its loaded keyring across its objects. Git helper subprocesses load
their own keyring rather than sharing process memory. While an external secret
command runs, SIGINT/SIGTERM cancel loading and clean up its process group. A
foreground terminal is temporarily handed to the loader and restored on return,
including exec failure. A terminal-attached background invocation fails explicitly
instead of stealing the terminal or hanging; use the foreground or detach the job.
Signal interception is scoped to this shared loading path, not unrelated blocking
CLI operations. SIGKILL/host death and deliberately escaped jobs remain outside
this cleanup guarantee. Python 3.8+ PTY regressions exercise both real CLIs.

Do not set multiple sources and expect precedence. The old backup-only
`BACKUP_SECRET_KEY`/`BACKUP_SECRET_KEY_FILE` names are removed. AWS/R2/server access
credentials are independent of these encryption keys and retain their ordinary
shared-profile/credential-process configuration.

## Compatibility

Backup supports FORMAT version 2. Version 1 is rejected without migration;
retained version 1 test fixtures require their original binary.

Existing git-remote-aws S3/DynamoDB layouts, SHA-1/SHA-256 histories, box keypairs,
and ciphertext remain readable. The recipient-stream wire format is unchanged. Strict
key-field syntax, committed recipient policy, and disjoint source selection are
intentional UI/configuration changes, not changes to old encrypted data. Retain your
original secret as the first generation when beginning a chain.

The helper adopts the selected tip's policy when the previously published commit
has no `.publickeys` entry. A present empty, malformed, or non-regular historical
entry is not absence and fails. This permits old untracked-policy histories to
advance without rewriting them; every new pushed tip must track its policy.
Backup's stricter canonical history always requires the recipient blob.
