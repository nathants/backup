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

### 6. [done] The R2 lock contract checks the probe prefix, not the backup namespace

**Location:** `integration/cloud_contract_test.go:142-175,357-391`.

The caller appends a random `contract-...` namespace to `config.prefix`, then passes that narrower `contractPrefix` into the lock audit. The audit accepts any indefinite rule covering that probe namespace.

For example, a rule covering `repository/contract-` passes this check for a configured `repository` backup prefix while leaving `repository/objects/...` and `repository/metadata/...` outside the protection being established. Destructive attempts against the locked probes cannot reveal that mistake.

**Evidence:** static argument/prefix trace, not a new live R2 result. This is a false-acceptance hole in the release gate; it does not establish that any particular deployed bucket currently has this configuration.

**Approved resolution:** the live R2 contract now passes the original configuration to `validateR2LockCoverage`, with no probe-prefix parameter in the lock-audit path. A nonempty configured prefix is checked as its object-key namespace with a trailing slash; an empty prefix remains empty and requires bucket-wide coverage. Enabled indefinite rules covering that namespace or a broader literal prefix remain valid. Random probe placement, existing negative control-plane checks, and runtime formats are unchanged; no automatic R2 configuration changes are added.

**Validation:** after extracting the existing coverage check without changing its decision, `TestR2LockCoverageUsesBackupNamespace` reproduced false acceptance of probe-stem, exact-probe, and bucket-probe-only locks (`shell/d6ab3e609f59fa69553ecdcd7889fe85/stdout` beneath the evidence directory above). The fixed check passes those rejections plus namespace/parent/bucket-wide positive controls, disabled/finite/sibling/data-only rejection, and the empty-prefix-versus-`/` boundary. `TestR2LockCoverageStillValidatesEveryRule` preserves malformed/missing-rule rejection even after a covering rule. Full `make check` passed on 2026-09-05, including mandatory lint/vet and the regressions under coverage and race (`shell/53db4ecf9c4a2107f13559a0e5894df8/stdout`). These cloud-free tests exercise the same helper as the live contract; no live R2 requests/settings changes were made and no real-account acceptance is claimed.

## Medium severity

### 7. [done] There is no completion-ledger rebuild path for a single mirror

**Location:** `internal/backup/sync.go:14-17,150-160`; `internal/backup/verify.go:48-69`; `internal/backup/capture.go:62-69`.

After the local ledger is lost, writer-only commit correctly refuses to guess. However, successful verification does not rebuild the ledger, and `Sync` requires distinct source/destination names. A supported one-mirror repository consequently cannot follow the error's instruction to “audit and sync a mirror first.” Sync also records only the destination, not the healthy audited source.

**Reproduced:** `TestReviewSingleMirrorLedgerRebuild`: delete only `completion-ledger.json`; verification passes with one complete mirror; self-sync is rejected; a subsequent real changed-file commit fails for lack of a known-complete mirror.

**Direction:** provide an explicit audited rebuild path, or let self-sync perform that audit without copying. Record the exact validated commit, preserve non-regression rules, and never infer completion from existence or `412`.

**Resolution and validation:** resolved as part of finding 3's approved fresh-audit policy. Successful current-tip `Verify` records exact per-mirror completeness even when the ledger was lost; successful `Sync` records both fully audited endpoints and retains its non-regression checks. Historical verification cannot clear a current quarantine. `TestIntegrityIncidentLedgerRebuildAndTransientFailures/single_mirror_rebuild` deletes the ledger, runs actual verification, and completes a changed-file backup. Full cloud-free and Docker/AWS gates passed as recorded under finding 3.

### 8. [done] Initialization is not resumable across its earliest Git-creation window

**Location:** `internal/repository/manage.go:71-90,96-112`; existing coverage at `internal/backup/backup_test.go:961`.

Git initialization and origin configuration are separate commands. A crash after `git init` but before `remote add origin` leaves `.git` present. The next `Init` enters the existing-repository path, where `OpenManaged` rejects the missing origin before recovery of an empty pre-genesis repository can proceed.

**Reproduced:** `TestReviewInitAfterGitInitCrash` runs the same SHA-256 `git init` into `.backup`, then invokes actual `Init`: `metadata Git remote does not match its trusted pin`. The existing early-init test calls the entire `repository.Initialize`, so it misses this window.

**Accepted manual intervention (2026-09-05):** Admin chose the preservation-first procedure now documented beside the genesis protocol in `NINA.md`, rather than an initialization redesign. In the confirmed fresh window, `Init` has only computed candidate metadata/UUID in memory and created Git setup files; operational staging, a durable genesis transaction, local commit, primary publication, and mirror uploads all occur after `repository.Initialize` returns. No acknowledged backup or meaningful backup staging is lost from this attempt. Previously used remote namespaces or damaged established repositories can nevertheless present the same missing/mismatched-origin error and must not be treated as disposable.

The procedure stops competing operations, preserves all metadata/state, inspects refs/objects/reflogs/candidates and trusted deployment history, resolves possible remote history read-only, and quarantines only positively identified unpublished setup residue before retrying. It explicitly rejects blind deletion and blind origin repair followed by `init`; the existing no-transaction/no-head branch can remove the directory. Remote-pin checks and later durable genesis resumability remain unchanged.

`[done]` means **accepted manual intervention**, not automatic crash recovery. The code limitation remains and the earlier private-build/atomic-publication proposal is superseded. Validation for this documentation-only resolution was a current call-path review (`init.go:21-131`, `repository/manage.go:71-114`, `commit.go:191-299`) and inspection of the retained reproduction above; no new crash test, runtime change, or destructive recovery action was performed.

### 9. [done] Symlink race handling both rejects legal filenames and leaks descriptors

**Location:** `internal/filesystem/scan.go:279-303,311-327`.

Two distinct defects:

a. The code treats every `/proc/self/fd` target ending in ` (deleted)` as an unlinked inode. That suffix is also legal in a live Linux filename. A symlink to `file (deleted)` therefore fails an otherwise valid scan. `TestReviewLiveDeletedSuffixSymlink` reproduces this with a stationary regular target.

b. A successful `Openat2` is followed by consistency checks that can return before the `defer Close(fd)` is installed. `TestReviewSymlinkRaceClosesResolvedFD` models replacement between the earlier stat and symlink classification and observes the descriptor count increase from 8 to 9. Repeated races during capture can accumulate leaked descriptors.

There is also a static policy mismatch at `326-327`: a resolved target failing canonical path validation is classified as a broken symlink rather than returning the required invalid-path error.

**Approved resolution:** target-descriptor cleanup is registered immediately after a successful open, before every consistency/error return. Scanning now checks link counts and re-resolves the original symlink with the same no-magic-link constraints, requiring matching device/inode and descriptor paths. This preserves literal ` (deleted)` filenames without confusing an unlinked dentry with a surviving hardlink—even one whose name equals the misleading proc-fd text. It adds one descriptor-only target lookup, not content reads or a new dependency. Invalid canonical targets now return escaped fatal errors instead of broken-link skips. Runtime formats and the existing capture retry/omission rules are unchanged.

**Focused validation:** `internal/filesystem/symlink_test.go` first reproduced live file/directory suffix rejection, three leaked descriptors after three classification races, and nonfatal omission of links to targets containing tab/LF/CR/invalid UTF-8 (`shell/7449b4d67067a4042754562357035533/stdout` beneath the evidence directory above). Those regressions now pass through actual `Walk`, `CapturePath`, and symlink classification. Deterministic post-open mutation tests additionally cover unlinks with/without a surviving hardlink, same-inode and different-inode replacement, directory removal, and capture retry outcomes. The full filesystem package and twenty focused race-detector repetitions passed (`shell/45f72cafa316b0299bca012f2529792d/stdout`, `shell/ed93b45dd308a9e473f67f57e504d29b/stdout`).

Full `make check` passed on 2026-09-05, including every mandatory linter, vet, coverage tests, and race tests (`shell/c531a948fef5aca3e2a935a9b5838e60/stdout` beneath the evidence directory above). No cloud deployment or runtime-format change was involved.

### 10. [done] Recovery repeatedly copies the entire growing Git graph, then repeats recovery again

**Location:** `internal/backup/metadata.go:388-439`, especially `411`; `internal/backup/recover.go:448-460,206-210`.

Every accepted metadata edge is imported into a new empty quarantine, first fetching the entire previously accepted graph. It then runs fsck over the enlarged graph and deletes the old copy. For a linear history whose graph grows by roughly constant increments, this repeats work over prefixes of sizes 1, 2, ..., N: quadratic cumulative graph processing rather than incremental edge processing.

Candidate verification subsequently discards the successfully reconstructed repository, retains the path description, and reconstructs/downloads the selected chain again for publication. This duplicates both network traffic and the expensive reconstruction. A mirror outage during the second pass can prevent publication after the first pass already recovered valid bytes.

**Evidence:** static algorithm/call-path analysis, not a measured production-scale slowdown.

**Approved resolution:** Admin chose one private repository per recovery attempt, with clean replay after a failed import, and authorized addressing measured large-history validation costs in this finding. Healthy imports extend that repository in place. A rejected physical representation is not retried within the logical path; replay is capped at 10,000 attempts. Failed attempts are removed before replay, not reset by moving refs. Candidate verification retains at most one possible publication repository plus the current attempt; a verified fork needs only commit-ID records because valid linear histories cannot later merge. Listing retains only IDs. Publication renames the exact verified repository from the destination filesystem instead of downloading/reconstructing the chain again.

The measured follow-up replaces repeated full-blob validation with native `git index-pack --stdin --fix-thin --strict` on each incoming pack, followed by connectivity and unreachable-object rejection at each exact edge. A final full strict Git check rehashes all stored objects before canonical history validation and publication; metadata repair retains its full final check too. This does not simply defer graph validation: objects injected early cannot become acceptable merely by becoming reachable later. Previously accepted local bodies are rechecked at the final boundary rather than after every edge. The existing bounded bundle-header parser supplies the pack stream; no third-party Git implementation, new dependency, format change, checkpoint scheme, or shared object-store quarantine was added. Git 2.36 source inspection showed that its bundle transport ignored `fetch.fsckObjects`, so the explicit strict indexer avoids silently relying on a newer-Git-only configuration behavior.

**Related failure found and fixed:** a genuinely post-import-invalid bundle reproduced quarantine cleanup failures. Git Trace2 showed detached automatic repacking racing removal of `objects/pack`; private quarantine initialization now disables `maintenance.auto`. Removal errors now identify the affected directory. Two older fixtures rejected at bundle-header validation rather than testing unreachable-object/failed-import cleanup; their assertions/naming are corrected, and a native pack containing an unadvertised unreachable blob exercises real imported-object rejection and clean replay.

**Focused validation:** the new public recovery regression first reproduced failure when a mirror goes offline after the chain has already been verified, for both anchored and default recovery; a separate regression observed multiple copied repositories on the healthy import path (`shell/4c69d7a264c08a405c57262cb2f4118d/stdout` beneath the evidence directory above). They now pass. Further actual-system tests cover exact part-read counts, post-import failure/replay without retained extra objects, malformed-commit rejection during strict import, final rejection of previously stored readable-but-wrong blob content, cancellation/report-failure cleanup, late-destination preservation, and listing without retained repositories. Native pack-reader controls cover successful and identical-repeat imports, nil/empty/truncated input, checksum damage, and trailing bytes. Focused final import/storage-fault checks passed in `shell/266292339156f68c32dce7e58bcadc39/stdout`.

**Exploratory scaling evidence (Git 2.55.0, local TLS object mirror):** synthetic valid metadata histories used many paths sharing one content mapping, then one mtime change per revision. These are metadata-recovery fixtures, not complete data backups or predictions of production recovery time. Setup was excluded; each measured case is one run, with native Git Trace2 enabled and no overlapping test campaign from this session. For 10,000 paths, the original code took 39.20 s at 32 revisions and 183.19 s at 128; option 3 alone took 9.40 s and 90.59 s. Its full checks still grew from 4.08 s to 67.27 s. The final validation approach took 5.46 s and 24.04 s, downloading each part once rather than twice. At 128 revisions, native tracing records 128 strict imports, 128 connectivity checks (0.74 s combined), and one full check (1.04 s), instead of 128 full checks. A larger 100,000-path/32-revision fixture completed in 23.19 s. These results remove the demonstrated repeated-blob-validation bottleneck; they do not claim asymptotically linear behavior for every graph/catalog shape.

Reproduction sources, pinned intermediate production files, overlays, per-case logs, and Git traces are retained under `scratch/recovery_scaling_test.go`, `scratch/run-recovery-profile.sh`, `scratch/recovery-profile-*.json`, and `scratch/recovery-profile-*/` beneath the evidence directory. Baseline/option-3 measurement output is `shell/94b48d56aeb256c9b14856c9b460a8a5/stdout`; final measurements are `shell/686d2f5d7a1028aff523b712da25726e/stdout`. Public-source research was cross-checked against directly retrieved Git 2.36/2.55 sources; the research transcript is `~/.nina/websearch/20260905T164441Z_2cea479af290b311.md`. No old-Git binary installation, storage power-loss experiment, or cloud deployment acceptance is claimed.

Full `make check` passed on 2026-09-05, including all mandatory linters, vet, coverage tests, and race tests (`shell/4e6ae197f77c655a486ffd4857624db5/stdout` beneath the evidence directory above).

### 11. [done] Cloud acceptance still has incomplete destructive/role coverage

**Location:** `integration/cloud_contract_test.go:187-269,292-334,399-407`.

The advertised contract is stronger than these tests establish:

a. R2 native lock mutation attempts use only the writer access-key ID and secret as bearer candidates; the reader credentials are never tested against that control plane, although the design explicitly requires both ordinary credentials to be unable to reach it.

b. AWS control-plane mutation tests exercise the writer only. Reader testing establishes failed object creation, not inability to delete or mutate bucket/IAM authority. Neither backend suite implements the required role-escalation attempts. `DeleteBucketEncryption` is tested for AWS, but `PutBucketEncryption` is not; SSE-C rejection is AWS-only.

c. The copy-overwrite attempt uses the protected probe itself as the source. The same contract establishes that the writer cannot read that source. A failed copy therefore does not distinguish missing source-read permission from destination overwrite protection. There is no positive source-read control.

**Evidence:** static test inventory. These are gaps in proof, not assertions that the checked-in AWS policy currently grants those powers.

**Direction:** map the explicitly required attacks to executable backend-specific cases, with applicable requests and separate ordinary-role coverage. For copy, use a source demonstrably readable by the attacking credential and verify the destination remains unchanged. Keep every mutation confined to the explicitly authorized destructive acceptance environment.

**Approved resolution:** Admin replaced the dual-role design with one ordinary read/list/create credential per AWS S3, R2, or backup-server mirror; administrative authority remains separate. Local configuration now requires eight fields, the server uses one credential, and obsolete role APIs/caches/environment fallbacks are removed. Canonical metadata, ciphertext, and operational-state formats are unchanged. The original separate-reader coverage requirement is superseded by this explicit design choice, not silently omitted.

The expanded contracts exercise the same ordinary credential for positive read/list/create and every applicable destructive attempt. Copy uses different, demonstrably readable source bytes. AWS adds encryption replacement, ACL/lifecycle mutations, ordinary and version-specific batch deletion, IAM user-policy escalation and credential issuance. R2 checks bucket-wide/prefix-wide indefinite locking and denies native lock/lifecycle/public-domain/bucket/token mutations using both S3 credential values as bearer candidates. SSE-C overwrite is tested on both clouds. Wrong-checksum rejection has a successful corrected-checksum control. Signature failures, malformed requests, generic conflicts, throttling, and arbitrary per-object batch errors cannot count as immutability evidence; accepted failures require specific authorization/lock codes. R2's recognized HTTP-400 authentication envelopes are distinguished from generic bad requests. Regression fixtures first reproduced the loose status/batch classifications and now pass.

**Validation:** full `make integration` passed on 2026-09-06, including `make check`, real Docker-server lifecycle/fault/two-mirror/whole-root tests, and live AWS plus R2 contracts both normally and under the race detector. Both clouds also completed real CLI genesis and two data revisions, checksum verification, broad/selected historical restore with content/mode/nanosecond-mtime/symlink/independent-inode checks, and latest plus anchored-genesis metadata recovery with the primary Git remote unavailable. All nine fuzz campaigns passed. The final cloud-free gate uses Admin's approved 30-minute per-package timeout after the former 10-minute budget expired during fsync under host contention; assertions, race checks, and durability settings were not weakened.

Private evidence is `<private-contract-evidence>`, with retained recovery fixtures and probe coordinates alongside it. Independent AWS/Docker inventory confirms the run-owned IAM user, bucket, containers, volumes, and image tags are gone. Independent checksum HEAD confirms both final R2 probes remain unchanged, and native lock readback matches the original bucket-wide indefinite rule. The new R2 test bucket retains 39 objects (45,639 bytes) plus tiny incomplete multipart probes because its lock also rejects their abort; protection was never disabled for cleanup. No existing unrelated Cloudflare bucket was mutated. This accepts the new test deployment and reusable suite, not existing production namespaces or the separate first-backup release gates.

### 12. [done] Several safety tests pass for the wrong reason

**Locations and reproduced problems:**

a. `internal/pack/pack_test.go:205-218`: the “canonical” archive names payload `x` with 128 `a` characters rather than its BLAKE2b. The unmodified baseline already fails plaintext verification. Both the trailing-data and missing-end-marker variants therefore pass their `err != nil` assertions without establishing the intended protection. `TestReviewTrailingTestHasValidBaseline` confirms the baseline hash mismatch. The encrypted trailing-ciphertext test at `269-298` uses the same invalid member identity and lacks a valid positive control.

b. `internal/format/format_test.go:314-318`: `MaxLineBytes=16` is combined with the larger default `MaxFieldBytes`. Parsing rejects the invalid limits configuration, not an overlong input record. `TestReviewLineLimitTestHasValidLimits` reports `maximum field size exceeds maximum line size`.

c. `internal/s3server/s3server_test.go:572-577`: the truncated-body request is passed directly to `ServeHTTP` with the outgoing URL's scheme/host intact. It receives `InvalidRequest: absolute request targets are unsupported` before body validation, satisfying the expected HTTP 400. `TestReviewTruncatedTestReachesBodyValidation` confirms that exact response. The preceding wrong-body case does traverse HTTP and is not the same false positive.

A related fuzzing weakness is static: `internal/pack/fuzz_test.go:14-36` has only empty/garbage ciphertext seeds and a zero secret. Random mutations will not cross the recipient/authentication barrier into authenticated framing and decompression. The separate canonical tar fuzz target is usefully seeded, but does not close this encrypted-reader gap.

**Direction:** require each baseline to succeed, mutate exactly one property, and assert the relevant error/observable boundary. Add valid recipient/ciphertext seeds and a separate structured authenticated-input fuzz path where needed. Do not respond by weakening production checks or merely adding more negative cases that fail earlier.

**Resolution:** test-only changes now require successful tar/encrypted baselines with the actual plaintext hash, then assert the specific framing, PAX, recipient, and trailing-ciphertext errors. Parser fixtures are otherwise valid, accept records exactly at their line/count bounds, and reject only the one-byte/one-record excess at the intended boundary. The direct server test has a successful incoming-request-shaped control, consumes the truncated body, requires `IncompleteBody` rather than generic HTTP 400, and retains the successful create retry proving no partial object was published; the wrong-body case explicitly requires `BadDigest`.

Encrypted fuzzing now includes a valid seed and fixed public test-only recipient so saved ciphertext remains replayable. The new `FuzzAuthenticatedPackReader` mutates either tar bytes before compression or compressed bytes before real encryption, exercising deeper readers without bypassing authentication. Positive seed controls must actually deliver the expected plaintext member. The target is included in `make fuzz`; fixture construction reuses the actual test tar/encryption helpers rather than reimplementing the readers.

**Validation:** strengthening assertions before correcting fixtures reproduced all four failures in `shell/993cc1e28f9a4cce61ac7dae9deca622/stdout` beneath the evidence directory above. Corrected targeted tests and all three affected packages pass; explicit encrypted/authenticated seed replays pass in `shell/10f2c28dbf21ade1482de06660492053/stdout`. Full `make check` passed on 2026-09-06, including mandatory linters, vet, coverage, and race tests. All ten `make fuzz` mutation campaigns passed with four workers. Final logs are `scratch/finding12-check.log` and `scratch/finding12-fuzz.log` beneath the evidence directory. Production code, runtime formats, dependencies, and security checks are unchanged; no new cloud deployment run was needed or claimed.

### 13. [done] Server logs discard internal causes and report successful HTTP status as zero

**Location:** `internal/s3server/server.go:234-267,329-382`.

`handle` converts internal errors to a generic status/code/message tuple. `ServeHTTP` only sees that tuple, so upload write/fsync/permission failures lose their actual cause even in the private structured log. Keeping the wire response generic is correct; discarding the operator-side cause is not.

Successful handlers return status zero as an internal sentinel, and that zero is emitted as the HTTP status. The response tracker records only whether headers were committed, not the actual status.

**Reproduced:** `TestReviewServerLogsInternalCause` injects an invalid temp descriptor; the HTTP 500 log contains only `internal server error`, with no EBADF or `create upload temp` context. `TestReviewServerLogsActualStatus` observes an actual HTTP 200 PUT logged as `"status":0`.

**Resolution (2026-09-06):** `handle` returns its underlying error to `ServeHTTP`, which independently maps the public response and emits one structured request log afterward. The response tracker retains the first final HTTP status, including implicit 200s and informational-header handling. Internal failures retain their cause at error level; public internal errors remain generic. Failures after a committed GET 200 keep that actual status, never append XML or rewrite the response, and no longer disappear from the operator log. Request-ID-generation and error-response-write failures use the same logging path. Free-text fields redact literal known credentials and received Authorization/security-token values plus their standard URL-path-escaped forms; structured encoding escapes controls. No protocol, credential, or storage format changed.

**Validation:** actual-handler regressions in `internal/s3server/logging_test.go` first reproduced the successful-PUT status zero, discarded EBADF cause, and committed-GET status/cause errors (`shell/cc4336961716f6b3f4065b43c1381a9e/stdout` beneath the evidence directory above). Fixed tests cover PUT/GET/HEAD/LIST, 403/404 responses, internal causes versus generic wire errors, partial-response and error-response write failures, randomness failure, known-value redaction/control escaping, and implicit/interim/first-final statuses. Full `make check`, all ten fuzz campaigns, and real Docker integration tests normally and under the race detector passed (`scratch/finding13-check.log`, `finding13-fuzz.log`, and `finding13-docker.log`). Docker coverage includes restart/immutability, two-mirror backup/sync/verify/restore/recovery, whole-root client operation, lost responses, malformed requests, backend symlinks, process kill, and disk-full failure. Independent inventory confirmed no run-owned containers, volumes, or image tags remained (`scratch/finding13-docker-cleanup.json`). No AWS/R2 requests or settings changes were needed for this server-logging fix; finding 11 retains that separate cloud acceptance evidence.

### 14. [done] The durable store's pathname writes contradict its descriptor-confined reads

**Location:** `internal/durable/store.go:25-37,50-92`; related separate atomic writers at `internal/repository/git.go:401` and `internal/repository/manage.go:450`.

`Open` runs pathname-based `MkdirAll` and `Chmod` before the no-follow open. `Write` retains a directory descriptor but uses `os.CreateTemp`/`os.Rename` against the original pathname, then fsyncs the retained descriptor. Reads use the descriptor correctly.

**Reproduced at the store API:**

a. `TestReviewOpenRejectsSymlinkWithoutChangingTarget`: opening a state symlink is rejected, but its outside target's permissions have already changed from `0755` to `0700`.

b. `TestReviewWriteUsesRetainedDirectory`: rename the opened state directory and replace the original path with a symlink. `Write` returns success after writing outside the retained directory and fsyncing the wrong directory for that publication.

**Boundary:** normal runtime prechecks and the private `.backup`/state directory make this less exposed than restore into an existing writable target. This is not a demonstrated remote-client exploit or a bypass through the ordinary initialization symlink test. It is a concrete API/contract flaw requiring access to the local parent namespace, and a source of false durability claims under path replacement.

**Resolution (2026-09-06):** the approved fix is localized to the durable JSON store. `Open` opens the existing parent, creates the final directory with `mkdirat`, opens it no-follow before `fchmod`, and fsyncs that directory and its parent. It no longer recursively creates ancestors; its sole production caller already prepares the metadata/state parent before opening the store. `Write` creates exclusive random no-follow temporaries with `openat`, renames and cleans them up relative to the retained descriptor, and fsyncs that same descriptor. Existing JSON bytes, final filenames, permissions, and transaction/ledger formats are unchanged. Existing store tests also close their descriptors on failure paths.

The operator must still exclusively control the local namespace and its ancestors. This is not resistance to a fully compromised same-user process, nor an application-wide guarantee against hostile pathname replacement. The original suggestion to consolidate other repository writers is superseded by this deliberately narrow scope; no Git/staging redesign or new abstraction framework was added.

**Validation:** new actual-store tests first reproduced the symlink-target chmod and redirected writes under both symlink and directory replacement (`shell/6bfb7ecc36b6bbdb5620b8159c9d7fca/stdout` beneath the evidence directory above). Fixed regressions verify retained-directory reads and reopening, unchanged outside content/permissions, private leaf/file modes without ancestor creation, descriptor-relative cleanup after failed rename, collision-safe temporary creation, and preservation of existing state on entropy failure. Focused normal/race tests and lint passed, followed by full `make check`, all ten fuzz campaigns, and Docker integration normally and under the race detector (`scratch/finding14-check.log`, `scratch/finding14-fuzz.log`, and `scratch/finding14-docker.log`). Real CLI two-mirror backup/sync/verify/restore/recovery and whole-root container tests passed. Independent inventory confirmed no run-owned Docker containers, volumes, or image tags remained (`scratch/finding14-docker-cleanup.json`). No cloud credentials, objects, or settings were touched for this local-state fix.

### 15. [done] Disaster recovery stops before a documented, tested usable client repository

**Location:** `internal/backup/metadata.go:262-266,295`; `internal/backup/recover.go:206-219`; `internal/backup/restore.go:69`; `integration/docker_test.go:433-449`; recovery commands in `NINA.md`.

Recovery publishes a bare Git repository with `refs/backup/recovered-tip` and a leftover candidate ref, but no branch under `refs/heads`. HEAD points at an unborn default branch. Ordinary restore still opens the managed checkout and fetches its configured primary. The runbook stops at producing `recovered.git`; it does not explain promotion of the selected validated tip, branch/HEAD setup, trusted remote repinning, or preparation of the checkout from which to restore.

**Reproduced:** `TestReviewRecoveredRepositoryHasUsableBranch` takes the original primary offline, successfully recovers genesis from the object mirror, and finds no branches, `HEAD=refs/heads/master`, and only the two private backup refs.

This is **not loss of recovered Git objects**: a knowledgeable operator can promote the ref manually. The gap is the last-mile disaster-recovery procedure and its acceptance test. Existing Docker coverage proves reconstruction and continued primary outage, not restoration using the reconstructed repository.

**Resolution (2026-09-06):** [the manual recovery-to-restore runbook](docs/recovery-restore.md) now covers preservation, trusted configuration and recipient prerequisites, external tip anchoring, create-only branch promotion/HEAD setup, a fresh non-hardlinked checkout, exact canonical file modes and local state exclusion, and explicit repinning to the recovered bare repository for rescue reads. It ends with ordinary verified restore into a fresh target. Original configuration, staging, source files, and the unavailable primary are preserved. Resource containment remains operator-owned. Production takeover is separate: retire the old writer, restore the mandatory primary authority, explicitly repin, and freshly verify to rebuild the ledger. No production code, recovery output format, offline-write mode, or installed Git wrapper was added.

**Validation:** `TestRecoveryRestoreRunbook` first reproduced a plain clone followed by restore failing with `couldn't find remote ref refs/heads/main`, for both latest and historical recovered tips (`shell/4178eb61256ca57d644531fc54ed1297/stdout` beneath the evidence directory above). The fixed test executes the runbook's Bash block verbatim with the real CLI and real server handler over verified TLS. It keeps the original checkout/source and primary unavailable; checks latest, anchored historical, and selected historical restores with content/mode/nanosecond-mtime/symlink/independent-inode assertions; rejects a mismatched anchor before branch/root creation; exercises sanitized Git despite misleading ambient `GIT_DIR`/`GIT_WORK_TREE`; preserves the trusted config; and observes no object PUTs during rescue. Final review also caught and reproduced a shell check accepting empty stdout from failed `git status` (`scratch/finding15-status-before.log`); the corrected assignment propagates its exit status, and the added regression requires stopping before restore. The Docker two-mirror test also executes the exact runbook, with the second mirror stopped, and restores latest and anchored historical data solely through the surviving container. Full `make check`, all ten fuzz campaigns, and the Docker suite normally and under the race detector passed. After the status-check correction, `make check` and both Docker modes passed again (`scratch/finding15-final-check.log`, `scratch/finding15-fuzz.log`, and `scratch/finding15-final-docker.log`). Independent inventory confirmed no run-owned Docker containers, volumes, or image tags remained (`scratch/finding15-final-docker-cleanup.json`). No AWS/R2 mutation or additional exact-production acceptance is claimed.

## Low severity / unnecessary complexity

### 16. [done] An unused cleanup API duplicates recursive removal and is already incorrect

**Location:** `internal/durable/store.go:119-208`; production counterpart `internal/securefs/remove.go`.

`Store.Reset` and its private recursive helper duplicate filesystem removal code, but repository-wide call-site inspection finds `Store.Reset` used only in its own tests, not by `backup reset`. It reads all directory entries at once and uses `Dup` on the retained descriptor. Duplicated descriptors share the directory offset, so a second reset can silently miss newly created entries.

**Reproduced:** `TestReviewResetTwice` writes a file, resets, writes it again, resets again; the second call returns success with the file still present.

The same shared-offset pattern appears in `filesystem.Root.scanDirectory` (`internal/filesystem/scan.go:137`) and `Spool.removeStaleFiles` (`internal/filesystem/spool.go:175`). Current ordinary scans open a fresh root, so this is not evidence that repeated CLI adds miss files, but the reusable APIs have a latent repeated-enumeration trap.

**Resolution (2026-09-06):** removed `Store.Reset`, its duplicate recursive helper, and tests specific to that unused API; retained the independent close-idempotency assertion in the store round-trip test. `backup reset` and its transaction-aware cleanup are unchanged. Scanner and spool enumeration now use `openat(fd, ".", ...)` with no-follow/directory/close-on-exec flags to obtain independent directory offsets. Scanner batches remain 256 entries; spool cleanup now also uses 256-entry batches while preserving filename, regular-file/owner, confinement, error, and fsync checks. No new abstraction, dependency, or format was added.

**Validation:** before the fix, actual-system regressions reproduced a reused root returning zero entries on its second walk, spool final cleanup missing 300 files created after initial preparation, and a new stale symlink reaching only `ENOTEMPTY` instead of the required type check (`shell/c429ab710bdf59102f76e3a12f376b36/stdout` beneath the evidence directory above). Fixed tests cover three walks of one root with creation/deletion between passes, multi-batch spool cleanup, and rejecting a newly introduced symlink without changing its target. Focused normal/race tests and lint passed, followed by full `make check`, all ten fuzz campaigns, and Docker integration normally and under the race detector (`scratch/finding16-check.log`, `scratch/finding16-fuzz.log`, and `scratch/finding16-docker.log`). Real CLI backup/reset/restore/recovery paths, including the recovery-to-restore runbook with primary outage, passed. Independent inventory confirmed no run-owned Docker containers, volumes, or image tags remained (`scratch/finding16-docker-cleanup.json`). No cloud resources were changed.

### 17. Mount reporting detects device changes, not every mount boundary

**Location:** `internal/filesystem/scan.go:130,175-179`.

The scanner compares `st_dev` with the parent device. A bind mount of another directory on the same filesystem has the same device number, so traversal proceeds without the required `mount-entered` diagnostic. This does not omit content, but it makes whole-root traversal less auditable than the design promises.

**Evidence:** static comparison logic and Linux bind-mount semantics; no mount was created on the host during this review.

**Direction:** use Linux mount identity, such as a suitable `statx` mount ID or a descriptor-consistent mount map, and cover same-device bind mounts in the isolated container test. Do not silently change traversal defaults.

## Design assessment and ordering

The largest problems are at boundaries: verified descriptor versus mutable name; local operator edits versus fetched metadata; positive ledger state versus later negative audit evidence; fsynced control state versus Git durability; and bounded Go parsers versus unbounded external Git work.

The cumulative catalogs, external sorting, one-file spooling, immutable relocation, mirror intersection, and explicit state-machine checkpoints are justified by the agreed format and durability requirements. Replacing them with an in-memory catalog, per-file remote objects, automatic catalog switching, or a new database would trade away settled invariants rather than simplify this implementation safely. Likewise, checksum-only protocol verification and append-only capacity growth are deliberate, not findings.

Prioritize the high-severity correctness/safety gaps, then repair the ledger/init recovery paths and misleading acceptance tests. The clearest simplifications are eliminating the duplicate recovery pass, avoiding repeated full-graph copying, deleting the unused recursive cleanup API, and consolidating safe atomic-file mechanics. Do not add another abstraction layer merely to hide these inconsistencies.
