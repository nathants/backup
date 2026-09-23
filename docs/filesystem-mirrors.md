# Filesystem mirrors

A `filesystem` mirror stores the same encrypted pack parts, encrypted metadata
bundle parts, and plaintext completion manifests as the network backends. It
needs no daemon, HTTP, TLS, or object-store credentials. The metadata Git primary
is still mandatory; production uses `git-remote-aws`.

## Security and storage requirements

Use a dedicated directory on ext4, exclusively controlled by the operator,
including its ancestors. The application never overwrites or deletes published
objects, but a compromised user with filesystem write access can do both. This
backend does **not** provide the ransomware boundary of a separately controlled
backup server or a correctly protected cloud mirror. Disconnecting an external
disk between operations reduces exposure; it does not protect a mounted disk.

Other filesystems, network filesystems, and Windows filesystem drivers are not
qualified for production. The code requires working file/directory fsync and
atomic `renameat2(RENAME_NOREPLACE)`; it does not substitute weaker operations.
Temporary-directory tests require no extra disk, mount, privileges, or cloud.
They do not qualify an external disk's controller, filesystem, or power-loss
behavior. Safely unmount a removable disk before disconnecting it.

One directory/store identity belongs to one repository and one mirror. Do not
share it with a running `backup server`. Do not configure multiple aliases or
copies of that store as different mirrors; initialize each additional mirror
separately. Configured filesystem mirrors require distinct identities and
non-overlapping directory paths. Different directories on one physical disk do
not provide independent failure protection.

## Initialize the destination

Mount the disk yourself. Backup never mounts it or silently creates a missing
store. For an external disk, require the actual mount point both at initialization
and in the trusted configuration:

```sh
mount="$HOME/mnt.SOMETHING"
mountpoint -q -- "$mount" || exit 1
mkdir -m 700 -- "$mount/backup"
backup mirror-init --directory "$mount/backup" --mount "$mount"
```

`mirror-init` requires an existing empty directory and prints:

```text
store   filesystem://0123456789abcdef0123456789abcdef
```

The printed identity is random. Use the actual value, not this example. It is
persisted in the bounded, regular `.backup-store` marker:

```text
backup-filesystem-v1
filesystem://0123456789abcdef0123456789abcdef
```

Initialization refuses every nonempty directory. If interrupted, preserve and
inspect its marker and any `.backup-tmp-*` residue; do not delete or reinitialize
an established or ambiguous store. A complete marker with the expected identity
can be reopened. Ordinary backup commands never replace or recreate a marker.

For an ordinary non-removable directory, omit `--mount` (equivalent to `-`). The
identity check remains mandatory. For a removable disk, keep the mount guard:
it uses opened-descriptor Linux mount IDs, requires the specified path to be a
non-root mount point, and requires the store to reside on that mount. No particular
device name is pinned, so remounting the same disk is supported. All path
components must be real directories, not symlinks.

## Configure and publish

Keep the existing `git-remote` and `branch` rows. A filesystem row has eight raw
tab-separated fields, ending in LF:

```text
mirror  local  filesystem  filesystem://STORE_ID  -  -  /home/USER/mnt.SOMETHING/backup  /home/USER/mnt.SOMETHING
```

For this backend the last two fields are **directory** and **required mount**,
not profile and CA file. Use canonical absolute paths; config does not expand
`~` or environment variables. `-` disables only the required-mount check.

The five-field tracked `mirrors.tsv` row is:

```text
local  filesystem  filesystem://STORE_ID  -  -
```

Examples above use spaces for readability; the actual files require tabs.
Mirror rows are sorted by name. The name/kind/store ID are permanent in metadata
history; the physical directory and mount paths are trusted local bindings and
may be explicitly changed when relocating the disk. Canonical metadata never
authorizes a filesystem path.

Before the first commit, an empty `mirrors.tsv` is filled from trusted config.
If you edit tracked mirror/recipient configuration, run `add` again. For ignore-only
edits, `replan` refreshes selection without rehashing known regular-file paths;
`diff` shows the replacement plan. No preceding `reset` is needed.
Configured destination directories under the source root are automatically
excluded, with a `filesystem-mirror-excluded` diagnostic. Local preparation
still permits an absent config; when supplied, config is validated for these
exclusions without opening a mirror or loading credentials. Commit rejects an
older saved plan containing a newly configured destination before capture (and
before first-publication binding). Run `add` again rather than discarding the
repository. Keep bind-mount/hardlink aliases of destination content outside the
source set or explicitly excluded; pathname exclusion is not alias discovery.
The source root must not itself be inside a configured store.

```sh
backup add --root /data
backup diff --root /data
backup commit --root /data
backup verify --root /data
backup verify --root /data --full
```

Ordinary verification recomputes BLAKE2b, SHA-256, MD5, and size from disk; it needs
no decryption secret. `--full` additionally verifies every catalog pack through
the actual decrypt/decompress/tar/plaintext-hash reader and reconstructs the exact
metadata tip in private Git quarantine. It requires an eligible secret source.
Only filesystem mirrors count toward `--minimum-mirrors` in full mode; network
mirrors remain checksum-only. Full pack verification streams ciphertext and
discards verified plaintext, with bounded file-backed catalog sorting. Metadata
reconstruction still requires temporary disk space and operator-owned aggregate
resource containment, just like `recover`. Retain and test keys for all required
historical ciphertext, not only the latest recipients.

Check a selected and broad restore and an anchored metadata recovery before
accepting the disk as a production destination. Local-only payload storage is
supported: one complete individual filesystem mirror can satisfy commit. It
provides only one disk's redundancy until additional mirrors are synchronized.

## Add cloud mirrors later

Provision and accept each remote backend according to its contract, add its row
to trusted config and tracked `mirrors.tsv`, then:

```sh
backup add --root /data
backup commit --root /data
backup sync --root /data --source local --destination aws
backup sync --root /data --source local --destination r2
backup verify --root /data --minimum-mirrors 3
```

No format conversion or plaintext recapture is needed. Sync copies identical
ciphertext and metadata-chain objects. Repair relocates healthy ciphertext to a
new immutable key, leaving old corrupt objects untouched. Recovery can use the
local disk even if the primary Git service and original checkout are unavailable.

## Durability and failure handling

Objects live at their logical keys directly below the store root:
`objects/HASH/ID`, `metadata/parts/HASH/ID`, and
`metadata/manifests/TIP/HASH/ID`. The backend exclusively locks the opened store
directory for each command, including reads, and closes it on completion.

Creation copies into a random private `.backup-tmp-*` file on the destination
filesystem, hashes and size-checks the copy, fsyncs it, creates/fsyncs parent
entries, publishes atomically without replacement, and fsyncs both directories.
A post-publication barrier failure is ambiguous, not an acknowledgement. Audits
hash existing bytes and flush their file/directory barriers before confirming
completion. File creation never hardlinks the source spool. The space-reserve
option applies to the destination as well as staging; free-space/inode checks
are estimates, not reservations. A full disk or I/O error must still fail safely.

Only unpublished recognized regular temp files are removed on the next write,
after taking the exclusive lock. Reads do not clean temps. Unexpected temp types
fail closed. Published objects are never removed. The root path and marker are
rechecked for each operation; a missing disk, wrong identity, changed directory,
or missing required mount is unavailable, not conclusive object corruption.
Normal incident/quarantine rules still apply to missing or corrupt required
objects on a successfully identified store.

Listings use bounded batched traversal and sorted logical keys, without a
persistent database or full-tree startup index. A listing is capped at one
million matching keys and a proportional directory-visit budget; exact-tip
metadata recovery prunes unrelated tips. These capacity limits can deny discovery
without changing known-key read access.
