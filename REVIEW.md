# Combined review: backup, git-remote-aws, go-libsodium

Reviewed 2026-09-08. Paths below are relative to the named repository.

## Scope and assessment

| Repository | Reviewed commit | Tracked files read |
| --- | --- | ---: |
| backup | `0c683263f274ba75caa24591ae6bcf1a90deb74c` | 127 / 127 |
| git-remote-aws | `9cdb990cbe58d18adf25d573b7010e109860ed85` | 17 / 17 |
| go-libsodium | `8bcc9badf0f46aea1641f54267242d44a7004ea0` | 18 / 18 |

Coverage includes complete source, tests, documentation, scripts, infrastructure definitions, module files, and the encrypted compatibility fixture. Generated/ignored build outputs are not source-review scope. File hashes were rechecked against the reading inventory. The applications' pinned go-libsodium commit, `165cd76c0d68`, differs from the reviewed library only in one comment.

The main problems are publication/evidence boundaries, inconsistent policies between components, and duplicated validation work—not the mere existence of a substantial state machine. The append-only object model, strict canonical parsers, descriptor-confined restore, durable progress, and failure-injection coverage serve concrete requirements. Another wholesale rewrite or a generic storage/transaction framework would not address the findings below.

High findings affect recoverability or durable transaction guarantees. Medium findings break supported workflows or impose substantial avoidable work. Low findings concern narrower contract, usability, or validation-maintenance problems. Executable reproductions and source-only conclusions are distinguished explicitly.

## Findings

### 1. Medium [done] — Unproven metadata representations could retire a pending bundle

**Reviewed locations:** backup `internal/backup/metadata.go:117–185`, `internal/backup/verify.go:46–73`, `internal/backup/incident.go:212–219`, `internal/backup/commit.go:159–170,322–376`.

On the reviewed source, `auditManifestChain` checked the manifest's declared UUID, sequence, base/tip and object checksums without establishing that the ciphertext actually reconstructed that Git edge. The manifest is public, unsigned, and self-hash-addressed: its hash establishes byte identity, not the truth of its declarations. An ordinary create credential can publish another internally consistent description of existing ciphertext.

**Reproduced on the reviewed source:** publish a healthy genesis, then interrupt a real snapshot immediately after confirmed primary Git publication but before its metadata edge is uploaded. Publish a new immutable manifest declaring that missing edge while referencing the existing genesis bundle bytes. No existing object is overwritten or deleted. Healthy genesis verification/recovery pass, and the missing-edge control fails. After the added manifest:

- `Verify(HEAD)` succeeds with one complete mirror;
- `Recover(--tip <same exact commit>)` rejects the bundle's advertised tip;
- resumed `Commit` nevertheless reports that mirror complete and deletes its real pending transaction/bundle staging.

**Severity correction:** this falsely completes an unfinished revision; it does not destroy an already healthy immutable chain. Surviving local/primary Git can regenerate the missing edge. The demonstrated impact is medium correctness/reliability, not the loss of previously successful backups through overwrite or deletion.

**Resolution:** implemented the narrow pending-transaction fix after rebasing onto backup `99a2aeb`. The existing staged manifest hash and object ID pin the only eligible representation for that pending Git edge in verification, sync, commit finalization, and forward-repair retirement. A ledger commit ID alone cannot authorize staging cleanup: commit freshly audits one individual mirror's complete candidate data and pinned metadata chain, with mandatory primary publication. Explicit metadata repair decrypts/imports and validates its rebuilt edge before publication, then atomically adopts durable replacement staging and actual destination acknowledgements into the pending transaction. Interrupted handoff preserves a usable old or new pin and retains old staging until transaction cleanup.

**Accepted remaining limit:** checksum-only audits of unfamiliar historical representations cannot prove that ciphertext reconstructs its declarations and can still mask an absent/damaged genuine edge. Adding false representations cannot overwrite or destroy a healthy immutable chain; actual recovery decrypts/imports and rejects them. No permanent provenance database, signing keys, encrypted-body downloads during protocol verification, object-format change, or additional restore prerequisite was introduced. This limited resolution and the accepted audit boundary are documented in `NINA.md` and `readme.md`.

**Permanent regressions:** `internal/backup/pending_metadata_test.go` exercises the actual backup APIs, Git, encryption and TLS server: missing/unrelated pending representations, stale ledger cleanup, forward repair, validated repair adoption and interruption replay, no-body verification, two-mirror pinned sync/fresh incident evidence, and primary-offline recovery. Targeted regressions and full `make check` passed.

### 2. High [done] — A failed helper manifest upload could advance the published DynamoDB pointer

**Reviewed locations:** git-remote-aws `main.go:154–178,299–319`; then-pinned go-dynamolock `dynamolock.go:285–307`.

On the reviewed source, `push` changed `repoMeta.BundlesS3Key` before uploading that object. If its `PutObject` failed, panic unwinding called deferred `unlock(..., repoMeta)`. Unlock was a conditional DynamoDB publication, not merely lock cleanup: it persisted the already-mutated pointer.

**Reproduced on the reviewed source:** a first real push succeeds. On the second push, the encrypted data bundle upload succeeds but the bundles-list upload receives an injected `403`. The actual deferred unlock publishes the new, never-created manifest key. Subsequent readers cannot even discover the previously healthy history through the current pointer. The old S3 objects survive, but ordinary operation requires repairing primary metadata. The original regression was `TestReviewFailedManifestPreservesPublishedPointer`.

**Resolution verified 2026-09-09:** the issue no longer applies to git-remote-aws `217db888506b3489ade1e80e148133a1ac3e9e5d`. Its push path calls `lease.Commit(ctx, repoMeta)` only after both S3 uploads succeed (`main.go:305–329`). Deferred cleanup instead calls bounded, independent `lease.Release(cleanup)` (`main.go:170–185`), preserving the original push error if release also fails. In the pinned go-dynamolock `40f0418786d9`, Release conditionally removes only ownership attributes and never writes `data` (`lease.go:325–382`). Mutating the local candidate therefore cannot publish it during cleanup. An ambiguous Commit is not retried as a payload write and cannot trigger deletion of the previous bundles list.

**Current validation:** all 11 `TestLeasePush` scenarios passed with `-race -count=1`, including rejected manifest upload, commit ambiguity, lease loss, no-op, and cleanup failures. The upload-failure case requires zero metadata commits, one release-only request, and zero S3 deletions. All 21 pinned-library `TestProtocol*` tests also passed with `-race -count=1`, covering release-only cleanup and ambiguous-write behavior. These exercise actual CLI/Git/crypto/SDK/lease code with scripted local provider responses; no live AWS contract or table migration was run. The review was limited to this finding's publication/cleanup boundary, not a new whole-repository review.

### 3. High [done] — Accumulated repair could save a transaction its own loader refused

**Reviewed locations:** backup `internal/backup/repair.go:123–148`, `internal/backup/transaction_files.go:39–49,195–224`, `internal/backup/runtime.go:171–225`.

Repair accumulation appended descriptors to an in-memory `DataParts` slice. The writer marshaled the entire slice into a content-addressed JSON file without the reader's size ceiling. Hydration later called `readStagedRef(..., 64<<10)`.

**Reproduced on the reviewed source:** 114 actual `RepairDataPart` calls, each interrupted at the durable candidate checkpoint, saved a valid relocation candidate with a 65,784-byte descriptor file. Saving succeeded; reopening returned `hydrate durable transaction files: invalid staged file reference`. `Reset` failed at the same loader. This is reachable through the supported accumulation path needed when several relocations must coexist before any individual mirror can be complete. The permanent regression also reproduced failure when repair 115 reopened the previously saved candidate.

**Resolution:** repair descriptors retain their existing hashed JSON-array format but are now streamed with a 64 KiB per-record/read-ahead bound and matching writer validation. The transaction retains only a file reference and a transient verified count, not the cumulative descriptor slice. Bounded external sorting detects duplicate parts/paths and performs subset/exact catalog validation; upload cursors retain append order. Appending or rotating a descriptor fsyncs a new content-addressed file before replacing the control record, preserving the previous candidate across failed publication. No operational-state schema or canonical backup-format change was needed.

**Permanent regressions:** `repair_progress_test.go` accumulates 128 real repairs in reverse catalog order, then verifies restart, commit/verification/restore, and reset. `repair_staging_test.go` checks interrupted descriptor/control publication, reuse of adopted bytes and IDs without another source download, and rejection of invalid/oversized descriptors, incorrect counts/reference sizes, duplicate parts/paths, and insufficient capacity without replacing usable control. `repair_records_test.go` checks streamed existing-format arrays, exact record bounds, malformed input, and the actual parser's fuzz seeds. Full `make check` and all `make fuzz` campaigns passed.

### 4. High [done] — New directory ancestry lacked an independent durability barrier

**Reviewed locations:** backup `internal/s3server/server.go:117–128,478–498,593–624`; `internal/repository/manage.go:65–68,807–820`.

**Source-level ordering finding; power-loss object loss was not experimentally reproduced.** On the reviewed source, `openOrCreateDirectory` immediately returned an existing directory without syncing its parent or coordinating with a concurrent creator. This permitted:

- request A creates an ancestor directory, then pauses before its parent fsync;
- request B opens that now-existing directory through the fast path, publishes below it and acknowledges after syncing only its own lower directories;
- A has still not completed the ancestor's durability barrier, or its fsync fails.

B's acknowledgement therefore depended on another request completing work that B neither waited for nor verified. A server-wide process lock does not serialize its concurrent requests. On filesystems requiring the explicit parent-directory fsync, the code had not established durable reachability of B's object.

There was a related setup gap: creating the server data root or the metadata `.backup` directory did not fsync that new directory's containing parent. Flushing descendants and the new directory itself is not an explicit barrier for that parent entry.

**Resolution:** every server create-path directory open now fsyncs its parent before returning a usable child descriptor, including observed-existing entries. Failed barriers prevent dependent object publication. Server-root and managed metadata initialization also sync their containing entries through the opened directory descriptor, avoiding pathname alias/trailing-slash mistakes. Missing managed setup ancestors are created and fsynced individually before descendants; retries flush existing parents without removing or replacing local state. No directory cache, new lock, journal, or backup-format change was introduced.

**Permanent regressions:** real Linux `O_PATH` descriptors reproduce missing existing-directory barriers and demonstrate that an ancestor fsync failure prevents final-key publication; a healthy retry completes through the existing-directory path. Unreadable containing directories exercise new/existing server and metadata roots, failure before Git setup, and retry. Additional tests cover trusted parent aliases, private nested setup directories, unrelated-data preservation, and descriptor-relative parent lookup after rename. These are syscall-failure/order checks, not simulated hardware power-loss evidence. The focused package race runs and full `make check` passed.

### 5. Medium [done] — Branch validation disagreed after the choice was durably pinned

**Reviewed locations:** backup `internal/localconfig/config.go:20,87–92`, `internal/backup/preparation.go:184–214`, `internal/backup/runtime.go:53–60`, `internal/repository/manage.go:149–181`; git-remote-aws `main.go:109–117,147–148,363`.

Two different failures shared the same late-validation problem:

- Backup accepted `archive/home`; its native-bare publication test successfully used that branch. The production helper rejected every slash-containing branch before push/fetch.
- Backup's regex also accepted Git-invalid `main.lock`. First commit persisted that choice, added `origin`, then failed at `git symbolic-ref`. Correcting the config to `main` made even `Reset` fail with `first publication remote does not match its durable pin`.

**Both reproduced**, including against helper `217db88` and backup `250f33d`. The latter occurred entirely locally, before remote publication. These configuration errors trapped preparation state rather than failing a correctable preflight.

**Resolution:** backup now invokes native `git check-ref-format --branch` through its hardened runner before persisting the first destination pin, and before managed initialization or initial remote binding can mutate Git setup. The bounded config grammar remains a lexical filter, not the authority for Git syntax. The helper uses the same native branch check through its cancelable Git runner, accepting valid slash names (`git-remote-aws` commit `122d311`). Both require the returned name to equal the literal input, rejecting contextual checkout-expression expansion. Existing durable destination pins, single-remote-branch enforcement, force-push rejection, and storage formats are unchanged; no preparation state is automatically deleted or repinned. Deploy the updated helper before using slash branches.

**Permanent regressions:** backup's `TestInitialInvalidBranchDoesNotPinPreparation` checks invalid names, unchanged preparation/add-plan/Git setup bytes, no object-client construction, and successful correction/reset/publication. Repository tests cover pre-mutation rejection, valid nested branches, and real reflog-expression expansion. The helper's `TestRefSlashBranchRoundTrip` exercises the actual CLI, Git, SDK and encryption with scripted local provider responses: first and incremental pushes, no-op, discovery, and fresh fetch of SHA-1/SHA-256 histories, plus retained single-branch and force protections. Native syntax, literal-name and cancellation tests also pass. Full backup `make check` and helper `GOTOOLCHAIN=local bash bin/check.sh` passed; no live AWS contract or installed-binary update was performed.

### 6. Medium [done] — Deleting the helper's previous bundles list broke concurrent readers

**Reviewed locations:** git-remote-aws `main.go:321–329,365–387,503–523`.

A reader loaded the current DynamoDB pointer and then performed a separate S3 GET. A successful writer published the next pointer and immediately deleted the previous bundles-list object. There was no reader coordination or retry that restarted pointer discovery.

**Reproduced:** hold an already-formed DynamoDB read response, complete a real healthy push, then release the reader. `list` followed its valid earlier pointer and failed with `NoSuchKey`. This did not depend on eventual consistency, a corrupt mirror, or two authoritative writers; one ordinary reader overlapped one writer. Permanent tests reproduced the same failure in `list`, `list for-push`, and `fetch` against `122d311`.

**Resolution:** bounded rediscovery, implemented in git-remote-aws `3ebf0a3`. Read-only discovery refreshes the pointer and bundle list together, with at most three total attempts. Only the SDK's typed S3 `NoSuchKey` from the list read triggers another attempt; message text, other HTTP 404 codes, access denial, malformed/truncated content, and missing encrypted bundle bodies do not. A lost pointer or changed branch during rediscovery fails rather than becoming an empty/new repository. The caller's cancellation context remains in force, and exhaustion preserves the missing-object error. Push still reads through its acquired lease and never substitutes an unleased pointer. Old cumulative lists continue to be deleted, avoiding indefinite cumulative-list storage; the CAS protocol, encrypted histories, and remote layout are unchanged.

**Permanent regressions:** `metadata_test.go` runs real CLI/Git/SDK/encryption code against scripted local provider responses, holding discovery while an actual writer publishes and deletes the previous list. It verifies successful rediscovery and fetch of the originally requested historical commit. Additional cases cover repeated advancement, unchanged absence, the exact retry cap, narrowly classified failures, pointer/branch loss, and cancellation. The existing lease suite also proves a missing list during push remains a release-only failure, not unleased rediscovery. Focused race regressions and full `GOTOOLCHAIN=local bash bin/check.sh` passed. No live AWS contract or installed-binary update was performed.

### 7. Medium — Library initialization races and treats successful native reinitialization as failure

**Reviewed locations:** go-libsodium `libsodium.go:24–27,50–58`; backup `internal/pack/pack.go:28,52`, `internal/metadatachain/chain.go:18,39`, `internal/backup/runtime.go:736`.

On the reviewed source, `Init` read/wrote a global Boolean without synchronization. Concurrent first callers could both enter `sodium_init`; its already-initialized return value is successful, but the wrapper panicked on every nonzero result.

**Reproduced:** 32 simultaneous actual `Init` calls in a fresh process produced a Go race report and `failed to init sodium` panics. The current serial CLI is not shown to hit this schedule. Separate `sync.Once` instances in different backup packages do not provide library-wide exclusion.

**Partial resolution:** local go-libsodium commit `1f9c1d0` owns initialization through `sync.OnceFunc`, accepts native results 0 and 1, and publishes readiness atomically. Native failure remains a panic for subsequent callers; explicit use-before-init rejection and the ciphertext format are unchanged. Fresh-process concurrent initialization and actual native-prior-initialization regressions reproduced the failures before the fix and pass afterward. Library lint, coverage, and full race tests passed.

**Remaining action, deferred:** the library fix is not published. Backup and git-remote-aws still pin `165cd76c0d68`, so this finding is not [done]. Once a published version is available, update both application pins, remove backup's redundant package guards, and run the application gates. No local dependency replacement or binary installation was made.

### 8. Low [done] — Trusted configuration and CA validation could block before rejecting a FIFO

**Reviewed locations:** backup `internal/localconfig/config.go:34–50`, `internal/objectstore/client.go:483–493`.

Both readers used blocking `O_RDONLY|O_NOFOLLOW` and inspected the file type only after opening. Opening a FIFO with no writer blocked before either regular-file check or size bound ran. A typo or damaged local setup could hang command startup rather than return the promised bounded-file error. The staged-file opener shared that blocking pattern and did not itself reject directories.

**Reproduced:** the original probes connected a writer to release the blocked production readers before cleanup. Permanent isolated-process regressions subsequently reproduced all three blocking opens against `44f3556` and staged-directory acceptance. This is low-severity local robustness, not a remote credential-redirection or backed-up-data corruption exploit; the original medium rating overstated its practical impact.

**Resolution:** add `O_NONBLOCK` to trusted config, custom CA, and staged-file opens; retain no-follow/confinement and existing validation. Staged opens now require a regular file through the opened descriptor and close rejected descriptors. Regular-file semantics, formats, and permissions are unchanged. No timeout, retry, new dependency, or filesystem abstraction was added to production code.

**Permanent regressions:** `TestLoadRejectsFIFOWithoutBlocking`, `TestTrustedCARejectsFIFOWithoutBlocking`, and `TestOpenStagedRejectsFIFOWithoutBlocking` invoke actual readers in bounded test processes with no FIFO writer. Staged directory/symlink rejection and intact regular-file reads are also covered. Focused race regressions and full `make check` passed.

### 9. Medium — Already validated history is repeatedly revalidated from genesis

**Locations:** backup `internal/backup/find.go:65–88`, `internal/backup/incident.go:131–141`, `internal/backup/commit.go:138–150`, `internal/repository/history_validate.go:108–181`.

`resolveHistoryRevision` receives a validated `History`, but any spelling other than literal `HEAD` creates a new validator without its ancestor cache, fully validates history, then asks the original history whether that commit belongs to it. `auditChain` passes an exact commit ID through this path for every mirror merely to obtain the repository UUID. Resume also constructs an uncached validator for the recorded local commit.

This is source-proven repeated parsing, Git subprocess work and cumulative-catalog transition validation—not just repeated hash comparisons. With growing history/catalogs, per-mirror local validation repeats historical catalog work that was already accepted before the audit. Using an exact externally recorded revision also takes a materially more expensive path than using `HEAD` for the same commit.

**Required action:** use immutable identity and membership information already supplied by validated history. Resolve a requested expression once, prove membership, and validate/load the selected state without re-walking every accepted ancestor. Retain full validation for newly accepted/untrusted history and the existing checks against local object corruption. Reuse the existing validated-ancestor mechanism on resumptions rather than adding another cache or validation subsystem.

### 10. Medium — The Git transport still embeds infrastructure convergence and its dependency graph

**Locations:** git-remote-aws `main.go:22,554–625`, `go.mod`; pinned go-dynamolock's import of `libaws/lib`.

The helper imports the full provisioning library for client/config helpers and `ensure=y`. Its compiled dependency graph includes 25 AWS service packages, including EC2, IAM, Lambda, ECS, Route53 and Organizations, although its storage protocol uses S3 and DynamoDB. Narrowing only the direct import would be insufficient while go-dynamolock retains the same dependency.

Every helper invocation also probes bucket/table setup before handling the Git protocol. Any discovery error is classified as “did not exist”; with `ensure=y`, it enters convergence even for permission, network or other non-absence failures. Without it, the diagnostic still falsely claims absence.

**Recommended simplification, requiring an explicit scope decision:** leave infrastructure convergence in the administrative `libaws` CLI and give the transport/lock library a narrow AWS client boundary. Preserve the existing credential discovery, CAS protocol and repository layout. At minimum, distinguish positively identified absence from all other discovery failures. A convenience setup option is not worth making the recovery-critical transport depend on an entire provisioning implementation.

### 11. Medium — Provisional add still requires source quiescence that final capture deliberately does not require

**Locations:** backup `internal/filesystem/scan.go:263–305,514–561`, `internal/backup/add.go:114`.

Add hashes to unbounded EOF, then rejects any change in size, timestamps, mode or other captured identity. Commit instead reads at most the open-time size once and records the actual readable bytes, warning about mutation. Thus an actively appended log or modified large file can prevent obtaining any add plan, so the mutation-tolerant commit semantics never become available. Add may also chase continuing appends rather than bounding its provisional read to the initial size.

**Source-level workflow/design finding, not a reproduced false-success bug.** A failed scan is currently safe; the problem is avoidable unavailability and two divergent file-observation policies. The design explicitly makes add provisional rather than a point-in-time snapshot.

**Decision needed:** either make provisional hashing bounded and mutation-tolerant, retaining fatal permission/I/O/unsafe-path failures and visible warnings, or explicitly document that add requires quiescent included files. Prefer reusing the established one-pass observation policy rather than another retry/stability mechanism. Do not introduce an mtime trust cache, silently skip changing files, or alter the saved lexical path-set rule.

### 12. Low — `find` retains an obsolete pending-publication restriction

**Locations:** backup `internal/backup/find.go:24–29`; compare `internal/backup/verify.go:19–23` and `internal/backup/restore.go`.

`find` rejects any transaction with `PushAttempted` and otherwise always requests a fetching/materializing head. Other read operations deliberately inspect the locally accepted validated tip during pending publication. `find` therefore becomes unavailable precisely when an operator may need to inspect the pending revision before verification or forward repair.

**Reproduced:** healthy `Find(HEAD)` works; after interrupting a real commit at `git-push-confirmed`, the same read fails with `a published transaction requires commit finalization before reading history`.

**Required action:** apply the same pending-transaction read policy as restore/verify, without materializing another tip over the transaction or weakening metadata validation.

**Regression:** `TestReviewFindWorksDuringPendingPublication`.

### 13. Low — TLS private-key mode checking has drifted from the stated contract

**Locations:** backup `cmd/backup/main.go:473–495`; compare go-libsodium `keysource/source.go:149–164`.

The TLS reader promises “mode 0600 or stricter” but only rejects group/other permissions and absence of owner-read permission. It accepts owner execution and setuid/setgid/sticky bits. The shared secret-file reader correctly rejects those extra bits.

**Reproduced:** `0500`, `0700`, and `0600` with each special bit are accepted; `0400` and `0600` positive controls also pass. This does not demonstrate disclosure to another user, but it violates the explicit private-file policy and illustrates duplicated security checks drifting apart.

**Required action:** enforce the actual allowed mode bits, including special bits. Share a small descriptor-based bounded-regular-file primitive where useful, keeping the different config/CA/private-key permission policies explicit rather than hiding them in a broad abstraction.

**Regression:** `TestReviewTLSPrivateKeyModeMatchesContract`.

### 14. Low — Subcommand help discards the information needed to operate the command

**Locations:** backup `cmd/backup/main.go:99–101,132–137`; `cmd/backup/main_test.go:26–50`.

All flag sets send their help output to `io.Discard`. The dispatcher replaces `flag.ErrHelp` with the generic command list. The real `backup restore --help` succeeds but documents none of `--target`, `--overwrite`, `--catalog-revision` or `--dry-run`, nor the restore positionals. Server and repair have the same discoverability problem. Tests currently assert generic help rather than useful command-specific output.

**Required action:** retain the relevant `FlagSet` usage/defaults and positional synopsis, including safety text. A small standard-library usage path is sufficient; a new CLI framework is unnecessary.

### 15. Low — Sibling check scripts are environment-mutating and partly advisory while appearing to be validation gates

**Locations:** git-remote-aws `bin/check.sh:4–45`; go-libsodium `bin/check.sh:4–45`.

Both scripts install missing tools with `@latest`, so running checks can change the machine and silently change lint policy. They run `go fmt` on the worktree, then suppress failures from several checks with `|| true`; `golint` diagnostics are additionally filtered. Their near-duplicate copies have already drifted. The mandatory staticcheck/ineffassign/errcheck/bodyclose/nargs/vet commands do fail on errors, so this is not a claim that every linter failure is ignored.

**Required action:** keep checks nonmutating, fail clearly when required tools are absent, and provision reviewed tool versions separately. Use format verification rather than in-place formatting. Remove low-value advisory checks or label them explicitly outside the gate. Keep the scripts short instead of building another lint orchestration layer.

### 16. Low — Universal tiny-part test defaults impose avoidable release-gate work

**Location:** backup `internal/backup/backup_test.go:45–95`.

The shared integration fixture defaults to an 8-byte pack target and 128-byte data and metadata parts. This forces even configuration/no-op/ordinary workflow fixtures through numerous actual uploads, fsyncs and durable acknowledgement transitions. Splitting tests need those sizes; most callers do not.

The unchanged `make check` run took 1,253 seconds, with the backup package taking 531 seconds for coverage and 703 seconds under the race detector. Those timings do not attribute all cost to fixture sizing, but the unnecessary splitting work is directly present in the defaults.

**Recommended simplification:** use ordinary single-part fixture sizes by default and request small parts explicitly in tests asserting splitting, partial acknowledgement, recovery edges or related crashes. Preserve real server/Git code, fsyncs, race coverage and all assertions. Measure the resulting gate improvement; do not mask latency with weaker durability or reduced test coverage.

## Original review validation evidence and limits

Reproduction tests were added only to exact-source private copies. Their failures above are assertions of desired behavior against the actual implementations, not replacement implementations of the algorithms. Backup probes use native Git and the real local TLS server; helper publication probes replace only the SDK transport and run separately where cached SDK clients require fresh processes. All keys and credentials in those fixtures are synthetic.

| Check | Result |
| --- | --- |
| backup `make check` on the reviewed, unchanged source | Passed: mandatory linters, coverage, race detector and vet; 1,253 seconds |
| go-libsodium coverage run | Failed once in `TestLoadCanceledCommandTerminatesChildren`: `child survived cancellation` |
| The same cancellation test, 100 focused repetitions | Passed |
| go-libsodium full race suite | Passed; the added fresh-process concurrent-Init regression separately fails |
| git-remote-aws cloud-free `TestKey*`, `TestBundle*`, `TestRef*`, `TestEncryption*` selection | Coverage and race runs passed; package coverage 29.3% |
| Both siblings: nonmutating staticcheck, ineffassign, errcheck, nargs, bodyclose, vet, formatting and build checks | Passed |
| Added correctness regressions described above | Reproduced the stated failures, with positive controls where applicable |

The cancellation failure remains an unresolved validation issue, not evidence that a persistent production child escape was demonstrated. `keysource/lifecycle_test.go:67–73` samples `/proc` immediately after the parent returns; asynchronous SIGKILL completion is a plausible timing explanation. Capture the child's subsequent state and use a bounded terminal-state assertion before calling this gate reliable. A later passing run does not erase the observed failure.

Docker integration, live AWS/R2 contracts, the AWS Git-primary/independent-old-helper gate, mutation fuzz campaigns, and advisory vulnerability checks were not run for this review. Cloud-free success is not deployment acceptance. In particular, the helper's small cloud-free coverage result leaves much of push/fetch dependent on cloud tests; retain fast actual-code local failure-injection regressions for findings 2 and 6.

The review does not reclassify explicitly accepted boundaries as defects: single authoritative writer, operator-owned aggregate restore/recovery containment, exclusive destination control, append-only capacity growth, the server's documented listing ceilings, and selection of an externally anchored last-known-good revision remain governing design choices. Shared key-chain parsing/loading, standard-library PAX handling and the distinct source-Git versus metadata-Git policies have concrete purposes and should not be collapsed merely to reduce line count.

Fix the high-severity evidence/publication/durability gaps before production acceptance. Resolve the explicit design decisions before implementing broad simplifications; keep the existing recoverability, immutability and no-unverified-publication invariants intact.
