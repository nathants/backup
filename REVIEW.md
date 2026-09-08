# Top-to-bottom review

Reviewed: 2026-09-04, repository commit `37479480ce0af88c52317db52369408f0dda7337`.

## Scope and evidence

Read all 93 tracked files in full, including production code, tests, dependency metadata, infrastructure, Docker/build scripts, license, and the authoritative design in `NINA.md`. Findings and line references describe that review baseline; `[done]` resolutions record subsequent approved fixes.

At the review baseline, `make check` **passed**: all mandatory linters, vet, coverage tests, and race tests. That result did not cover the defects below. Sixteen additional focused assertions against actual system code failed in the review overlay, establishing behavioral defects, misleading test fixtures, and the recovery-output gap. The overlay does not modify repository sources or the existing test suite.

Evidence directory:

```text
/home/nathants/.nina/runs/home_nathants_repos_backup_c0e244c3f665a430_20260904T225927Z_rpqMI
```

- Existing gate: `shell/f22aff85de1f6b5377744a48c879970e/stdout`.
- Consolidated reproductions: `shell/26aae23337d020a9717d0da90eeb7590/stdout`.
- Reproduction sources and overlay: `scratch/review_*test.go`, `scratch/review-overlay.json`.

To rerun the focused assertions from this checkout, substitute the evidence directory for `EVIDENCE`:

```sh
./integration/cloud-free-env.sh go test \
  -overlay "$EVIDENCE/scratch/review-overlay.json" \
  ./internal/backup ./internal/filesystem ./internal/pack \
  ./internal/s3server ./internal/format ./internal/durable \
  -run '^TestReview' -count=1 -v
```

These assertions express the missing behavior and exit nonzero on the review baseline; individual assertions may pass after the corresponding fixes. Static findings are labeled separately; no power-loss experiment, hostile Git resource-exhaustion experiment, mutation fuzz campaign, Docker integration, or live cloud destructive contract was run for this review.

## High severity

### 1. [done] Restore can follow a substituted temporary symlink and publish an unverified inode

**Location:** `internal/backup/restore.go:244-307`, especially `289` and `298-301`; analogous name-based symlink publication at `310-354`.

`publishRegular` verifies bytes through an open temporary-file descriptor, but applies the timestamp through `UtimesNanoAt(parentFD, temporary, times, 0)`. That call follows symlinks. It subsequently renames the temporary **name**, not necessarily the inode it verified. Existing destination parents need not be private to the restoring process.

A process with write access to that parent can replace the temporary entry while the original descriptor remains open. Substituting a symlink makes restore change the timestamp of a file outside the target and then publish the symlink as a supposedly verified regular file. Substituting another regular inode also breaks the verified-content publication guarantee. Descriptor-relative parent traversal and `RENAME_NOREPLACE` do not prevent substitution of the source name.

**Reproduced:** `TestReviewRestoreTempSubstitution` swaps the temp during the destination copy. `publishRegular` returns success, the destination is a symlink, and the outside file's mtime becomes `1700000000123456789`. A FIFO only schedules the copy window deterministically; the publication code is unmodified. This requires a concurrent destination-directory writer, not merely malicious archive metadata. It does not apply to an exclusively controlled target tree.

**Original direction:** apply metadata through the verified descriptor; protect the publication source in a private staging directory/inode scheme rather than a writable parent namespace. Explicitly establish the destination-writer trust boundary, including renamed parent directories. A last-second `lstat` alone is another race, not a solution. Add concurrent temp-substitution coverage for both file and symlink publication.

**Approved resolution:** Admin chose straightforward hardening for exclusively controlled restore destinations, not defenses against adversarial concurrent destination writers. Regular-file timestamps now use the verified descriptor with `AT_EMPTY_PATH` (Linux 5.8+), and a no-follow device/inode/type comparison rejects detected temporary-entry substitution before rename. CLI help, the API comment, and `NINA.md` explicitly require exclusive control of the destination namespace and its ancestry throughout restore, for both regular files and symlinks. The inode check is defense in depth, not an atomic race-prevention mechanism; concurrent writers remain outside this agreed boundary.

**Validation:** `TestRestoreRegularPublicationRejectsChangedTemporaryEntry` first reproduced publication of substituted symlinks/regular files and outside timestamp modification. All eight cases now pass, including positive controls and both overwrite modes; ten race-detector repetitions also pass. `TestRestoreHelpStatesExclusiveDestinationRequirement` and the actual `go run ./cmd/backup restore --help` output confirm the visible safety requirement. Full `make check` passed on 2026-09-04; evidence is `shell/befc54689178ebfda051dd54c7284255/stdout` beneath the evidence directory above.

### 2. [done] Fetching a newer revision silently destroys local configuration edits

**Location:** `internal/backup/runtime.go:578-613`; `internal/backup/add.go:41-61`.

`validatedHead(true)` fast-forwards by calling `ApplyCommit` before checking the worktree. `Add` checks status and reads `ignore`, `.publickeys`, and `mirrors.tsv` only afterward. The fetched tree has already replaced those files. The same helper is used by operations such as find, verify, restore, and sync, so even ostensibly observational commands can discard edits.

This is more than an editor inconvenience: a locally added exclusion can disappear, causing `add` to select material the operator specifically intended not to back up. Removed recipients can similarly reappear in the candidate configuration.

**Reproduced:** `TestReviewFetchPreservesIgnore` advances the remote through a valid descendant, locally writes `^\./secret$`, and runs `Add`. It succeeds, replaces the local ignore file with the remote version, and includes `./secret` in `DiffCandidate`.

**Direction:** inspect and preserve/refuse dirty state against the current local revision before materializing fetched metadata. Do not silently merge security-sensitive configuration or restore remote bytes over operator edits. Test remote advancement together with mutable and unrelated dirty files.

**Resolution:** the shared fetched-tip path now checks the existing validated local-head worktree status before calling `ApplyCommit`. Dirty paths are reported with escaped quoting, with no materialization intent or local branch update. This protects all callers of that path without changing commit/reset materialization or the normal mutable-configuration workflow when the remote is unchanged.

**Validation:** regressions in `internal/backup/fetch_test.go` first reproduced the overwrite and now pass for each mutable configuration file, a catalog edit, missing/type/mode changes, and an unrelated untracked file. Actual `Add` coverage preserves an existing plan and exclusion after refusal; actual `Find` coverage rejects dirty state and accepts a clean retry against a differing remote tree. Full `make check` passed on 2026-09-05, including the new tests under the race detector; evidence is `shell/ae56881c609b2ffa1170bd53316d40fc/stdout` beneath the evidence directory above.

### 3. [done] A mirror proven corrupt remains eligible for later successful backups

**Location:** `internal/backup/verify.go:48-69`; `internal/backup/capture.go:62-71`; `internal/backup/commit.go:369-370,654`.

Verification reports corruption but never invalidates the completion ledger. Later capture trusts the same old complete-through-base record and deduplicates against the old catalogs. New uploads and metadata completion can therefore turn a mirror already known to be missing/corrupt into a reported complete mirror without repairing the affected bytes.

**Reproduced:** `TestReviewVerifyRevokesKnownCorruptMirror` creates a revision, corrupts one referenced pack part, observes a failed `Verify`, adds a different file, and commits. Commit reports `CompleteMirrors=[local]`; verifying that exact new revision immediately fails. The old corrupt part remains referenced.

The issue is **known negative evidence being ignored**, not a demand to download/audit every historical object on every writer-only backup.

**Direction:** durably revoke affected completeness eligibility after a conclusive failed integrity audit, and reconcile any staged candidate-complete state that depends on it. Restore eligibility only through an appropriate successful audit/sync/repair. Distinguish corruption/missing objects from transient unavailability rather than treating every network error as established data loss.

**Approved resolution:** each repository/prefix now has one authoritative writer checkout/ledger by operational convention, without leases or hostname enforcement. Confirmed current-object damage durably quarantines a mirror and atomically invalidates pre-incident completeness records. A fresh full current audit can restore eligibility to healthy mirrors; writer-only backups then continue with prominent degraded-redundancy reporting. Typed missing/corrupt outcomes distinguish real negative evidence from unavailable credentials, transport failures, or unsupported checksums. The server exposes conclusive checksum-HEAD corruption through a dedicated response header; superseded historical mappings and healthy alternate metadata representations do not cause spurious quarantine. Capture/candidate progress is re-audited after incidents, including acknowledged data lost during pending publication.

Verification, restore, sync, and metadata repair remain usable during pending publication. Explicit forward data repair preserves the pending published commit and its verified recovery-bundle chain before retiring its transaction, leaves a durable ordinary-backup block across restart gaps, and reports success only for a complete repair descendant. Several necessary relocations can accumulate in one unpublished repair candidate. Full candidate-data/base-metadata audits avoid demanding a falsely healthy corrupt base. Git publication and reset/CAS protections remain mandatory. A fresh full audit may complete a pending tip through an alternate bundle representation without inventing staged acknowledgements. Operational state is a hard cutover to version 3; canonical backup formats are unchanged.

**Validation:** actual-system regressions in `internal/backup/incident_test.go` first reproduced corrupt/missing-mirror acceptance and pending-publication acceptance, then passed after the fixes. Coverage includes fresh-audit restart, stale candidate acknowledgements, missing acknowledged pending parts, writer-only degraded operation, single-mirror ledger rebuild, multi-part repair, historical restore with explicit relocation, alternate metadata repair, pending genesis, refusal without unintended publication, and five forward-repair restart boundaries. Each restart case also decrypts/reconstructs the preserved chain with primary Git offline; restore checks confirm exact content and no publication on corrupt input. Objectstore tests distinguish conclusive failures from unavailable checksum capabilities and generic HTTP failures.

Full `make check` passed on 2026-09-05, including the final application code under coverage and the race detector (`shell/dcd90c0905d2a71f08575d2b77127ea9/stdout`). `make integration` passed Docker and scratch-account AWS contracts normally and under race, including the real two-mirror client and isolated whole-root client (`shell/60da116d0e272c37c2a0492d60950b25/stdout`). R2 was not enabled. Independent AWS/Docker checks confirmed cleanup of the run's bucket, users, containers, volumes, and image tags (`shell/414ed58849e9372309c587f4ea377d2d/stdout`, `shell/b0cc52d85a60bbff28e72e003f066311/stdout`). These paths are beneath the evidence directory above; no production deployment acceptance or storage power-loss test is claimed.

### 4. [done] The durable state machine relies on Git writes that are not durably configured

**Location:** `internal/repository/git.go:215-229`; `internal/repository/manage.go:71-90,151-219`; `internal/backup/commit.go:150-185`.

Canonical blobs, trees, and commits are created with Git plumbing, and their commit ID is then saved in fsynced transaction state. Neither the hardened Git invocation nor initialization pins `core.fsync`/`core.fsyncMethod`. There is no corresponding explicit hardening of those newly written Git objects and references before the durable control record depends on them.

The installed Git manual warns that unhardened components can be lost after an unclean shutdown. Its aggregate descriptions are stale: Git v2.55.0 source defines `committed` as objects plus references, while its default excludes loose objects and references (`write-or-die.h`). Explicit component names avoid this documentation/aggregate drift. Atomic worktree file replacement or fsync of a transaction file is not a durability contract for separate Git object/ref files.

**Evidence:** static call-path review plus the installed `git-config(1)` documentation. Process-restart checkpoints passed, but they do not simulate loss of dirty kernel/storage caches. No actual power-loss failure is claimed.

**Impact:** a durable transaction can remember a local commit whose objects or branch update were not durable. Resume may fail before bundling/pushing it, despite the surrounding fsync machinery.

**Approved resolution:** pin `core.fsync=objects,reference` and `core.fsyncMethod=fsync` in every hardened invocation. A once-per-process bounded version preflight requires Git 2.36 or newer (where both settings were introduced), rejects unknown versions and failed checks, and retains the checked executable path. Existing command failure handling remains exact-exit-based; opening a managed repository preserves compatibility errors instead of misreporting them as an object-format mismatch.

Admin explicitly chose configuration-only local crash-resumability hardening and accepted storage-dependent sync latency, excluding custom journaling/reconstruction, a storage-crash framework, or broader durability redesign. The original high-severity placement overstates the risk to acknowledged backups: a completed revision already has mandatory primary Git publication plus a complete independently recoverable object mirror. This fix primarily protects local pending-state recovery after OS crashes/power loss; an ordinary process crash does not discard the kernel page cache. It does not prove every directory/storage power-failure case.

**Validation:** `internal/repository/durability_test.go` first reproduced disabled settings and absent Git hardware-flush events, then passed with the fix. Real Git 2.55.0 Trace2 confirms flush calls for newly written loose objects and references despite repository-local disabling settings; configuration tests also cover hostile ambient overrides. Compatibility tests use version-response fixtures for minimum/vendor/future versions, old/malformed/missing Git, bounded output, warning/nonzero-exit failures, and refusal before bare initialization. A real Git lock conflict remains a nonzero write error and leaves the reference unpublished. The full repository package and `make check` (all mandatory linters, vet, coverage, and race tests) passed on 2026-09-05; final check evidence is `shell/f414b927d452d1bca3b442301ea903ba/stdout` beneath the evidence directory above. No fsync-error injection or power-loss experiment is claimed.

### 5. [done] Recovery's resource bounds stop at the Git subprocess boundary

**Location:** `internal/backup/recover.go:51-79,573-585`; `internal/backup/metadata.go:269-298,406-421`; `internal/repository/git.go:215-229`.

Manifest sizes and encrypted/plaintext bundle bytes are bounded, but the decrypted Git pack is passed to `git fetch` and `git fsck` before canonical blob/tree/history validation. The runner uses `exec.Command` without a context deadline or subprocess memory/disk/CPU enforcement. Bounding captured stdout is not a bound on Git's object inflation, delta reconstruction, object counts, or internal allocations.

`recoveryWorkspaceRequirement` estimates quarantine storage from encrypted bundle sizes and part counts, not enforced capacity. Git's bundle transport retains compressed packs rather than extracting every object uncompressed; indexes, thin-pack reconstruction, temporary copies, and history-validation files still consume additional storage. Memory/CPU exhaustion is the clearest hostile-input risk. A compromised writer with a recipient public key can construct decryptable hostile input without the recovery secret. Checksums and encryption authentication reject ordinary corruption but do not prove benign intent.

**Accepted operational responsibility (2026-09-05):** Admin explicitly assigns aggregate resource containment to the operator. `NINA.md` now requires an appropriately resource-bounded environment when restoring potentially malicious backups or recovering/importing suspect metadata, including `backup recover --list`, which imports candidate chains. The environment must cover the whole command and descendants, temporary work, and destination storage; `--tip`, private directories, and free-space estimates do not substitute for enforced limits. Existing integrity validation and safe-publication requirements remain unchanged.

`[done]` records this accepted responsibility, **not implementation or proof of binary-enforced containment**. No built-in sandbox, runtime containment enforcement, automatic provisioning, or installation is added. The implementation limitation remains; operational budgets must accommodate legitimate large histories. The original suggestion to add internal resource enforcement and a stress framework is superseded by this decision.

**Evidence:** read-only call-path review and Git/Linux source/documentation cross-checks; no resource-exhaustion payload or containment acceptance test was executed. This resolution changes governing documentation and review status only.

### 6. The R2 lock contract checks the probe prefix, not the backup namespace

**Location:** `integration/cloud_contract_test.go:142-175,357-391`.

The caller appends a random `contract-...` namespace to `config.prefix`, then passes that narrower `contractPrefix` into the lock audit. The audit accepts any indefinite rule covering that probe namespace.

For example, a rule covering `repository/contract-` passes this check for a configured `repository` backup prefix while leaving `repository/objects/...` and `repository/metadata/...` outside the protection being established. Destructive attempts against the locked probes cannot reveal that mistake.

**Evidence:** static argument/prefix trace, not a new live R2 result. This is a false-acceptance hole in the release gate; it does not establish that any particular deployed bucket currently has this configuration.

**Direction:** check coverage of the exact configured backup namespace independently of the random probe location. Handle an empty configured prefix as the entire bucket namespace, not `/`. Add a regression case where only `repository/contract-` is locked and acceptance must fail.

## Medium severity

### 7. [done] There is no completion-ledger rebuild path for a single mirror

**Location:** `internal/backup/sync.go:14-17,150-160`; `internal/backup/verify.go:48-69`; `internal/backup/capture.go:62-69`.

After the local ledger is lost, writer-only commit correctly refuses to guess. However, successful verification does not rebuild the ledger, and `Sync` requires distinct source/destination names. A supported one-mirror repository consequently cannot follow the error's instruction to “audit and sync a mirror first.” Sync also records only the destination, not the healthy audited source.

**Reproduced:** `TestReviewSingleMirrorLedgerRebuild`: delete only `completion-ledger.json`; verification passes with one complete mirror; self-sync is rejected; a subsequent real changed-file commit fails for lack of a known-complete mirror.

**Direction:** provide an explicit audited rebuild path, or let self-sync perform that audit without copying. Record the exact validated commit, preserve non-regression rules, and never infer completion from existence or `412`.

**Resolution and validation:** resolved as part of finding 3's approved fresh-audit policy. Successful current-tip `Verify` records exact per-mirror completeness even when the ledger was lost; successful `Sync` records both fully audited endpoints and retains its non-regression checks. Historical verification cannot clear a current quarantine. `TestIntegrityIncidentLedgerRebuildAndTransientFailures/single_mirror_rebuild` deletes the ledger, runs actual verification, and completes a changed-file backup. Full cloud-free and Docker/AWS gates passed as recorded under finding 3.

### 8. Initialization is not resumable across its earliest Git-creation window

**Location:** `internal/repository/manage.go:71-90,96-112`; existing coverage at `internal/backup/backup_test.go:961`.

Git initialization and origin configuration are separate commands. A crash after `git init` but before `remote add origin` leaves `.git` present. The next `Init` enters the existing-repository path, where `OpenManaged` rejects the missing origin before recovery of an empty pre-genesis repository can proceed.

**Reproduced:** `TestReviewInitAfterGitInitCrash` runs the same SHA-256 `git init` into `.backup`, then invokes actual `Init`: `metadata Git remote does not match its trusted pin`. The existing early-init test calls the entire `repository.Initialize`, so it misses this window.

**Direction:** retain a resumable initialization intent before the first mutation, or stage and atomically publish a fully configured empty repository. Only repair an authenticated/recognizably task-owned partial initialization; do not weaken the remote-pin check for arbitrary existing repositories.

### 9. Symlink race handling both rejects legal filenames and leaks descriptors

**Location:** `internal/filesystem/scan.go:279-303,311-327`.

Two distinct defects:

a. The code treats every `/proc/self/fd` target ending in ` (deleted)` as an unlinked inode. That suffix is also legal in a live Linux filename. A symlink to `file (deleted)` therefore fails an otherwise valid scan. `TestReviewLiveDeletedSuffixSymlink` reproduces this with a stationary regular target.

b. A successful `Openat2` is followed by consistency checks that can return before the `defer Close(fd)` is installed. `TestReviewSymlinkRaceClosesResolvedFD` models replacement between the earlier stat and symlink classification and observes the descriptor count increase from 8 to 9. Repeated races during capture can accumulate leaked descriptors.

There is also a static policy mismatch at `326-327`: a resolved target failing canonical path validation is classified as a broken symlink rather than returning the required invalid-path error.

**Direction:** install cleanup immediately after a successful open; use inode/link-state and consistency checks rather than an ambiguous printable suffix to identify deletion; preserve fatal validation errors for noncanonical paths. Test genuine unlinks separately from literal suffixes.

### 10. Recovery repeatedly copies the entire growing Git graph, then repeats recovery again

**Location:** `internal/backup/metadata.go:388-439`, especially `411`; `internal/backup/recover.go:448-460,206-210`.

Every accepted metadata edge is imported into a new empty quarantine, first fetching the entire previously accepted graph. It then runs fsck over the enlarged graph and deletes the old copy. For a linear history whose graph grows by roughly constant increments, this repeats work over prefixes of sizes 1, 2, ..., N: quadratic cumulative graph processing rather than incremental edge processing.

Candidate verification subsequently discards the successfully reconstructed repository, retains the path description, and reconstructs/downloads the selected chain again for publication. This duplicates both network traffic and the expensive reconstruction. A mirror outage during the second pass can prevent publication after the first pass already recovered valid bytes.

**Evidence:** static algorithm/call-path analysis, not a measured production-scale slowdown.

**Direction:** retain the selected verified repository and publish it. Isolate failed physical alternatives without copying all accepted objects on each edge—for example, a carefully managed candidate object quarantine over a read-only accepted object store. Keep failed-alternative contamination tests and exact-history validation. Periodic full checkpoints are not necessary to address this implementation cost.

### 11. Cloud acceptance still has incomplete destructive/role coverage

**Location:** `integration/cloud_contract_test.go:187-269,292-334,399-407`.

The advertised contract is stronger than these tests establish:

a. R2 native lock mutation attempts use only the writer access-key ID and secret as bearer candidates; the reader credentials are never tested against that control plane, although the design explicitly requires both ordinary credentials to be unable to reach it.

b. AWS control-plane mutation tests exercise the writer only. Reader testing establishes failed object creation, not inability to delete or mutate bucket/IAM authority. Neither backend suite implements the required role-escalation attempts. `DeleteBucketEncryption` is tested for AWS, but `PutBucketEncryption` is not; SSE-C rejection is AWS-only.

c. The copy-overwrite attempt uses the protected probe itself as the source. The same contract establishes that the writer cannot read that source. A failed copy therefore does not distinguish missing source-read permission from destination overwrite protection. There is no positive source-read control.

**Evidence:** static test inventory. These are gaps in proof, not assertions that the checked-in AWS policy currently grants those powers.

**Direction:** map the explicitly required attacks to executable backend-specific cases, with applicable requests and separate ordinary-role coverage. For copy, use a source demonstrably readable by the attacking credential and verify the destination remains unchanged. Keep every mutation confined to the explicitly authorized destructive acceptance environment.

### 12. Several safety tests pass for the wrong reason

**Locations and reproduced problems:**

a. `internal/pack/pack_test.go:205-218`: the “canonical” archive names payload `x` with 128 `a` characters rather than its BLAKE2b. The unmodified baseline already fails plaintext verification. Both the trailing-data and missing-end-marker variants therefore pass their `err != nil` assertions without establishing the intended protection. `TestReviewTrailingTestHasValidBaseline` confirms the baseline hash mismatch. The encrypted trailing-ciphertext test at `269-298` uses the same invalid member identity and lacks a valid positive control.

b. `internal/format/format_test.go:314-318`: `MaxLineBytes=16` is combined with the larger default `MaxFieldBytes`. Parsing rejects the invalid limits configuration, not an overlong input record. `TestReviewLineLimitTestHasValidLimits` reports `maximum field size exceeds maximum line size`.

c. `internal/s3server/s3server_test.go:572-577`: the truncated-body request is passed directly to `ServeHTTP` with the outgoing URL's scheme/host intact. It receives `InvalidRequest: absolute request targets are unsupported` before body validation, satisfying the expected HTTP 400. `TestReviewTruncatedTestReachesBodyValidation` confirms that exact response. The preceding wrong-body case does traverse HTTP and is not the same false positive.

A related fuzzing weakness is static: `internal/pack/fuzz_test.go:14-36` has only empty/garbage ciphertext seeds and a zero secret. Random mutations will not cross the recipient/authentication barrier into authenticated framing and decompression. The separate canonical tar fuzz target is usefully seeded, but does not close this encrypted-reader gap.

**Direction:** require each baseline to succeed, mutate exactly one property, and assert the relevant error/observable boundary. Add valid recipient/ciphertext seeds and a separate structured authenticated-input fuzz path where needed. Do not respond by weakening production checks or merely adding more negative cases that fail earlier.

### 13. Server logs discard internal causes and report successful HTTP status as zero

**Location:** `internal/s3server/server.go:234-267,329-382`.

`handle` converts internal errors to a generic status/code/message tuple. `ServeHTTP` only sees that tuple, so upload write/fsync/permission failures lose their actual cause even in the private structured log. Keeping the wire response generic is correct; discarding the operator-side cause is not.

Successful handlers return status zero as an internal sentinel, and that zero is emitted as the HTTP status. The response tracker records only whether headers were committed, not the actual status.

**Reproduced:** `TestReviewServerLogsInternalCause` injects an invalid temp descriptor; the HTTP 500 log contains only `internal server error`, with no EBADF or `create upload temp` context. `TestReviewServerLogsActualStatus` observes an actual HTTP 200 PUT logged as `"status":0`.

**Direction:** retain the underlying error until structured logging, sanitize sensitive data, and separately map it to the public response. Track the actual response status, including already-started responses and implicit 200s.

### 14. The durable store's pathname writes contradict its descriptor-confined reads

**Location:** `internal/durable/store.go:25-37,50-92`; related separate atomic writers at `internal/repository/git.go:401` and `internal/repository/manage.go:450`.

`Open` runs pathname-based `MkdirAll` and `Chmod` before the no-follow open. `Write` retains a directory descriptor but uses `os.CreateTemp`/`os.Rename` against the original pathname, then fsyncs the retained descriptor. Reads use the descriptor correctly.

**Reproduced at the store API:**

a. `TestReviewOpenRejectsSymlinkWithoutChangingTarget`: opening a state symlink is rejected, but its outside target's permissions have already changed from `0755` to `0700`.

b. `TestReviewWriteUsesRetainedDirectory`: rename the opened state directory and replace the original path with a symlink. `Write` returns success after writing outside the retained directory and fsyncing the wrong directory for that publication.

**Boundary:** normal runtime prechecks and the private `.backup`/state directory make this less exposed than restore into an existing writable target. This is not a demonstrated remote-client exploit or a bypass through the ordinary initialization symlink test. It is a concrete API/contract flaw requiring access to the local parent namespace, and a source of false durability claims under path replacement.

**Direction:** make state creation, chmod, temp creation, rename, cleanup, and directory fsync consistently descriptor-relative. Consolidate genuinely common atomic-publication behavior rather than maintaining byte-writer, stream-writer, and JSON-writer variants with different confinement semantics.

### 15. Disaster recovery stops before a documented, tested usable client repository

**Location:** `internal/backup/metadata.go:262-266,295`; `internal/backup/recover.go:206-219`; `internal/backup/restore.go:69`; `integration/docker_test.go:433-449`; recovery commands in `NINA.md`.

Recovery publishes a bare Git repository with `refs/backup/recovered-tip` and a leftover candidate ref, but no branch under `refs/heads`. HEAD points at an unborn default branch. Ordinary restore still opens the managed checkout and fetches its configured primary. The runbook stops at producing `recovered.git`; it does not explain promotion of the selected validated tip, branch/HEAD setup, trusted remote repinning, or preparation of the checkout from which to restore.

**Reproduced:** `TestReviewRecoveredRepositoryHasUsableBranch` takes the original primary offline, successfully recovers genesis from the object mirror, and finds no branches, `HEAD=refs/heads/master`, and only the two private backup refs.

This is **not loss of recovered Git objects**: a knowledgeable operator can promote the ref manually. The gap is the last-mile disaster-recovery procedure and its acceptance test. Existing Docker coverage proves reconstruction and continued primary outage, not restoration using the reconstructed repository.

**Direction:** document and test the exact manual promotion/setup/restore sequence, or publish a normal branch/HEAD if that is the intended command contract. Keep the mandatory primary concurrency authority for new backups; an offline-write mode is not needed. Finish the test by restoring actual content solely from the recovered metadata and surviving mirror.

## Low severity / unnecessary complexity

### 16. An unused cleanup API duplicates recursive removal and is already incorrect

**Location:** `internal/durable/store.go:119-208`; production counterpart `internal/securefs/remove.go`.

`Store.Reset` and its private recursive helper duplicate filesystem removal code, but repository-wide call-site inspection finds `Store.Reset` used only in its own tests, not by `backup reset`. It reads all directory entries at once and uses `Dup` on the retained descriptor. Duplicated descriptors share the directory offset, so a second reset can silently miss newly created entries.

**Reproduced:** `TestReviewResetTwice` writes a file, resets, writes it again, resets again; the second call returns success with the file still present.

The same shared-offset pattern appears in `filesystem.Root.scanDirectory` (`internal/filesystem/scan.go:137`) and `Spool.removeStaleFiles` (`internal/filesystem/spool.go:175`). Current ordinary scans open a fresh root, so this is not evidence that repeated CLI adds miss files, but the reusable APIs have a latent repeated-enumeration trap.

**Direction:** delete the unused store reset API and duplicate recursive remover instead of extending a dead abstraction. For live repeated enumeration, open a new directory description rather than duping a consumed one; retain bounded entry batches.

### 17. Mount reporting detects device changes, not every mount boundary

**Location:** `internal/filesystem/scan.go:130,175-179`.

The scanner compares `st_dev` with the parent device. A bind mount of another directory on the same filesystem has the same device number, so traversal proceeds without the required `mount-entered` diagnostic. This does not omit content, but it makes whole-root traversal less auditable than the design promises.

**Evidence:** static comparison logic and Linux bind-mount semantics; no mount was created on the host during this review.

**Direction:** use Linux mount identity, such as a suitable `statx` mount ID or a descriptor-consistent mount map, and cover same-device bind mounts in the isolated container test. Do not silently change traversal defaults.

## Design assessment and ordering

The largest problems are at boundaries: verified descriptor versus mutable name; local operator edits versus fetched metadata; positive ledger state versus later negative audit evidence; fsynced control state versus Git durability; and bounded Go parsers versus unbounded external Git work.

The cumulative catalogs, external sorting, one-file spooling, immutable relocation, mirror intersection, and explicit state-machine checkpoints are justified by the agreed format and durability requirements. Replacing them with an in-memory catalog, per-file remote objects, automatic catalog switching, or a new database would trade away settled invariants rather than simplify this implementation safely. Likewise, checksum-only protocol verification and append-only capacity growth are deliberate, not findings.

Prioritize the high-severity correctness/safety gaps, then repair the ledger/init recovery paths and misleading acceptance tests. The clearest simplifications are eliminating the duplicate recovery pass, avoiding repeated full-graph copying, deleting the unused recursive cleanup API, and consolidating safe atomic-file mechanics. Do not add another abstraction layer merely to hide these inconsistencies.
