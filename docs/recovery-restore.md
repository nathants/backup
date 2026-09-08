# Restore after losing the primary Git service

Read this after `backup recover` has successfully reconstructed a selected tip from
an object mirror. Recovery reconstructs **metadata**, not source files. Its output
is a bare Git repository with `refs/backup/recovered-tip`, not a ready-to-use
`.backup` checkout. Do not run `backup init`: that would request a new repository
identity rather than recover the old one.

## Before proceeding

1. Use an exclusively controlled, private workspace and ancestors. Preserve any
   old checkout, operational ledger, pending transactions, source files, and
   configuration separately; do not reset, clean, delete, or overwrite them.
   Neither the original source tree nor the original primary is needed below.
2. Keep an eligible historical private key chain,
   ordinary mirror credentials, trusted mirror topology, and CA roots available.
   `TRUSTED_CONFIG` below is your independently trusted local configuration, **not**
   routing information copied from recovered `mirrors.tsv`. It must contain the
   pins/profiles needed for the selected history. Canonical topology cannot
   authorize new credential destinations.
3. For potentially malicious backups, apply the operator-owned aggregate resource
   limits in [Restore safety](../NINA.md#restore-safety) to recovery, listing, Git
   promotion/clone, and restore, including descendants, `TMPDIR`, and destination
   storage. A private directory alone supplies no resource containment.
4. Obtain a successful recovery using the existing commands, for example
   `backup recover --root /safe/config-root --config /safe/trusted-config --mirror local --tip COMMIT --destination /safe/recovered.git`.
   This requires no existing `.backup` in the config root. `--list` can discover
   candidates, but after suspected compromise select an externally retained
   last-known-good commit explicitly; structural validity does not prove intent.
   Retain the reported exact 64-hex `recovered-tip` and compare it with that anchor.
5. Set these shell variables to reviewed values before running the block:

   - `RECOVERED`: absolute path to the fresh successful recovery output.
   - `TIP`: exact recovered commit ID, independently checked as above.
   - `BRANCH`: the branch from the trusted configuration, typically `main`.
   - `TRUSTED_CONFIG`: absolute path to the preserved trusted local config.
   - `RESCUE_ROOT`: a **nonexistent** absolute path beneath the private workspace,
     separate from the preserved data, config, and recovered bare repository.
   - `BACKUP_BIN`: optional path to the reviewed binary; defaults to `backup` on PATH.

   Configure one shared [secret source](key-management.md#load-secrets-on-demand)
   and the ordinary AWS credential profiles. No provider administrator credential
   is needed. **Check the secret lookup identity before repinning:** recovery uses
   the original trusted `git-remote` argument, but the restore below passes the
   exact local `$RECOVERED` path to a command loader. A URL-pinned loader must not
   silently select a different secret or treat that path as another repository.

   For an on-demand source, prepare a private rescue executable that accepts only
   this exact `$RECOVERED` path and invokes your original loader with the original
   trusted remote URL. For example, with those two literal values substituted:

   ```sh
   #!/bin/sh
   [ "$#" = 1 ] && [ "$1" = '/safe/recovered.git' ] || exit 2
   exec /private/original-loader 'aws://original-bucket+table/repository'
   ```

   Make it executable only by you. Before the rescue block, unset
   `GIT_REMOTE_AWS_SECRETKEY` and `GIT_REMOTE_AWS_SECRETKEY_FILE`, then set
   `GIT_REMOTE_AWS_SECRETKEY_CMD` to that rescue executable. Keep the original source
   for any further `recover` invocation using the original config. This is an
   explicit local operator mapping, never routing inferred from recovered metadata.

   Alternatively, select an already retained eligible private-chain file with
   `GIT_REMOTE_AWS_SECRETKEY_FILE`, clearing both other sources. No new plaintext
   secret file is required when using the on-demand mapping. Apply the same source
   selection to subsequent selected/historical restores from this rescue checkout.

## Manual promotion, local repinning, and restore

The commands use the recovered bare repository as a **temporary local metadata
source for rescue reads**, not as authorization to resume production writes. They
create one branch without replacing an existing branch, set HEAD, clone without
hardlinks/alternates, prepare a clean seven-file checkout, and create a separate
local config. Only `git-remote` is redirected to the recovered repository; the
trusted branch and mirror rows retain their intended identities. The old config
and primary are untouched.

This block is executed verbatim by the cloud-free and Docker runbook tests. It is
a manual procedure, not an installed wrapper or a new backup subcommand. Git is
invoked with a clean environment and explicit hooks/attributes/durability settings;
only the already-validated recovered tree is checked out.

```bash
set -euo pipefail
umask 077
: "${RECOVERED:?}" "${TIP:?}" "${BRANCH:?}" "${TRUSTED_CONFIG:?}" "${RESCUE_ROOT:?}"
BACKUP_BIN=${BACKUP_BIN:-backup}
[[ $RECOVERED == /* && $TRUSTED_CONFIG == /* && $RESCUE_ROOT == /* ]]
[[ $TIP =~ ^[0-9a-f]{64}$ ]]
[[ ! -e $RESCUE_ROOT && ! -L $RESCUE_ROOT ]]
# Tabs/newlines cannot appear in trusted-config fields.
[[ $RECOVERED != *$'\t'* && $RECOVERED != *$'\r'* && $RECOVERED != *$'\n'* ]]

git_cmd=(env -i "PATH=$PATH" "HOME=$RESCUE_ROOT" "TMPDIR=${TMPDIR:-/tmp}"
  LC_ALL=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
  git --no-pager --literal-pathspecs --no-replace-objects
  -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null
  -c core.autocrlf=false -c core.eol=lf -c core.filemode=true -c core.symlinks=true
  -c core.fsync=objects,reference -c core.fsyncMethod=fsync
  -c maintenance.auto=false -c gc.auto=0)
"${git_cmd[@]}" check-ref-format "refs/heads/$BRANCH"
[[ $("${git_cmd[@]}" -C "$RECOVERED" rev-parse --is-bare-repository) == true ]]
[[ $("${git_cmd[@]}" -C "$RECOVERED" rev-parse --show-object-format) == sha256 ]]
if [[ $("${git_cmd[@]}" -C "$RECOVERED" rev-parse --verify refs/backup/recovered-tip) != "$TIP" ]]; then
  printf 'recovered-tip does not match TIP; stop and check the external anchor\n' >&2
  exit 1
fi
"${git_cmd[@]}" -C "$RECOVERED" update-ref "refs/heads/$BRANCH" "$TIP" "$(printf '%064d' 0)"
"${git_cmd[@]}" -C "$RECOVERED" symbolic-ref HEAD "refs/heads/$BRANCH"

mkdir -- "$RESCUE_ROOT"
"${git_cmd[@]}" clone --no-local --no-checkout --single-branch --branch "$BRANCH" \
  --template= -- "$RECOVERED" "$RESCUE_ROOT/.backup"
"${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" checkout "$BRANCH" --
for name in FORMAT index.tsv objects.tsv packs.tsv ignore .publickeys mirrors.tsv; do
  chmod 0644 -- "$RESCUE_ROOT/.backup/$name"
done
mkdir -p -- "$RESCUE_ROOT/.backup/.git/info"
printf '/.backup-state/\n' > "$RESCUE_ROOT/.backup/.git/info/exclude"
# Persist basic checkout hygiene; retain git_cmd for further manual Git work.
"${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" config core.hooksPath /dev/null
"${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" config core.autocrlf false
"${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" config maintenance.auto false
[[ $("${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" rev-parse HEAD) == "$TIP" ]]
[[ $("${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" remote get-url origin) == "$RECOVERED" ]]
worktree_status=$("${git_cmd[@]}" -C "$RESCUE_ROOT/.backup" status --porcelain --untracked-files=all)
[[ -z $worktree_status ]]

# Preserve exact trusted mirror rows; never substitute recovered routing metadata.
{
  printf 'git-remote\t%s\nbranch\t%s\n' "$RECOVERED" "$BRANCH"
  awk -F '\t' '$1 == "mirror" {print}' "$TRUSTED_CONFIG"
} > "$RESCUE_ROOT/.backup-config"
chmod 0600 -- "$RESCUE_ROOT/.backup-config"
mkdir -- "$RESCUE_ROOT/restored"
"$BACKUP_BIN" restore --root "$RESCUE_ROOT" --target "$RESCUE_ROOT/restored" '^\./' "$TIP"
```

Every selected regular file is verified before publication by the ordinary restore
implementation. Compare expected content, modes, timestamps, and symlinks; retain
its printed snapshot/catalog IDs. For a selected or historical restore, use another
fresh target and an explicit regex/commit with the same rescue root. Do not
implicitly change catalogs to bypass a missing historical part; use the documented
explicit `--catalog-revision` rule when a compatible relocation is needed.

A failure stops the block. Preserve both repositories and any output, diagnose the
reported step, and continue only after checking its state. Do not add `--force`,
reset an existing branch, delete an existing rescue root, or blindly rerun the
entire block. An interrupted restore may have published an exact subset of complete
verified files; honor its report and default no-overwrite behavior.

## Returning to production is a separate decision

Do not run add/commit/sync/repair through this rescue checkout. Restore alone does
not establish a healthy completion ledger or make this machine the writer. This
procedure changes no remote objects and does not create a new Git-history edge.

Before enabling a replacement writer, retire/revoke the old writer, preserve and
resolve any pending published history, restore the mandatory production Git
concurrency authority using the selected validated history, explicitly repin the
replacement checkout/configuration, and freshly verify the mirrors to rebuild the
ledger. Do not force an older selected tip over an established primary. A
historical rescue selection is not automatically the right tip for continued
production. Keep provider administration separate and follow the deployment and
single-writer requirements in [NINA.md](../NINA.md).
