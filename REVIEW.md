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

### 3. High — Accumulated repair writes durable state that its own loader refuses

**Locations:** backup `internal/backup/repair.go:123–148`, `internal/backup/transaction_files.go:39–49,195–224`, `internal/backup/runtime.go:171–225`.

Repair accumulation appends descriptors to `DataParts`. The writer marshals the entire slice into a content-addressed JSON file without the reader's size ceiling. Hydration later calls `readStagedRef(..., 64<<10)`.

**Reproduced:** 114 actual `RepairDataPart` calls, each interrupted at the durable candidate checkpoint, save a valid relocation candidate with a 65,784-byte descriptor file. Saving succeeds; reopening returns `hydrate durable transaction files: invalid staged file reference`. `Reset` fails at the same loader. This is reachable through the supported accumulation path needed when several relocations must coexist before any individual mirror can be complete.

**Required action:** give repair progress a bounded-record/segmented representation with symmetric writer/reader validation. At minimum, reject unsupported state before replacing the control record, leaving the previous transaction usable. Merely increasing a magic whole-file limit postpones the defect and leaves the ever-growing slice.

**Regression:** `TestReviewAccumulatedRepairRemainsLoadable`; no invented transaction JSON or replacement implementation is used.

### 4. High — New directory ancestry lacks an independent durability barrier

**Locations:** backup `internal/s3server/server.go:117–128,478–498,593–624`; `internal/repository/manage.go:65–68,807–820`.

**Source-level ordering finding; power-loss object loss was not experimentally reproduced.** `openOrCreateDirectory` immediately returns an existing directory without syncing its parent or coordinating with a concurrent creator. This permits:

- request A creates an ancestor directory, then pauses before its parent fsync;
- request B opens that now-existing directory through the fast path, publishes below it and acknowledges after syncing only its own lower directories;
- A has still not completed the ancestor's durability barrier, or its fsync fails.

B's acknowledgement therefore depends on another request completing work that B neither waits for nor verifies. A server-wide process lock does not serialize its concurrent requests. On filesystems requiring the explicit parent-directory fsync, the code has not established durable reachability of B's object.

There is a related setup gap: creating the server data root or the metadata `.backup` directory does not fsync that new directory's containing parent. Flushing descendants and the new directory itself is not an explicit barrier for that parent entry.

**Required action:** establish durable directory publication before any dependent acknowledgement, including the concurrently observed-existing case. A small directory-creation critical section or explicit parent synchronization is sufficient; no custom journal is needed. Sync newly created root entries as well. Add syscall/fault-ordering coverage; process-kill/restart tests alone do not establish power-loss ordering.

### 5. Medium — Branch validation disagrees across all three publication boundaries, after the choice is durably pinned

**Locations:** backup `internal/localconfig/config.go:20,87–92`, `internal/backup/preparation.go:184–214`, `internal/backup/runtime.go:53–60`, `internal/repository/manage.go:149–181`; git-remote-aws `main.go:109–117,147–148,363`.

Two different failures share the same late-validation problem:

- Backup accepts `archive/home`; its existing native-bare publication test successfully uses that branch. The production helper rejects every slash-containing branch before push/fetch.
- Backup's regex also accepts Git-invalid `main.lock`. First commit persists that choice, adds `origin`, then fails at `git symbolic-ref`. Correcting the config to `main` makes even `Reset` fail with `first publication remote does not match its durable pin`.

**Both reproduced.** The latter occurs entirely locally, before any remote publication. These are configuration errors that turn into trapped preparation state rather than a correctable preflight failure.

**Required action:** validate full Git branch syntax and backend compatibility before writing the durable destination pin. Align the helper with valid Git branch names rather than maintaining an unnecessary slash restriction. Retain destination pinning and the preservation-first treatment of existing state; do not solve this by deleting preparation state automatically.

**Regressions:** `TestReviewInvalidGitBranchDoesNotPinPreparation`, `TestReviewPushSupportsBackupSlashBranch`; positive control `TestInitialRemoteBindingIsPinnedAcrossRestart` passes with the native remote.

### 6. Medium — Deleting the helper's previous bundles list breaks concurrent readers

**Locations:** git-remote-aws `main.go:321–329,365–387,503–523`.

A reader loads the current DynamoDB pointer and then performs a separate S3 GET. A successful writer publishes the next pointer and immediately deletes the previous bundles-list object. There is no reader coordination or retry that restarts pointer discovery.

**Reproduced:** hold an already-formed DynamoDB read response, complete a real healthy push, then release the reader. `list` follows its valid earlier pointer and fails with `NoSuchKey`. This does not depend on eventual consistency, a corrupt mirror, or two authoritative writers; one ordinary reader overlaps one writer.

**Required action:** stop deleting manifests that in-flight readers can still reference, or make readers restart from current metadata on this specific race. Retaining these small historical lists is the simpler cutover. This finding is about reader availability, not applying the object mirrors' append-only policy to the separate primary Git service.

**Regression:** `TestReviewReaderSurvivesConcurrentManifestPublication`, run in a fresh test process.

### 7. Medium — Library initialization races and treats successful native reinitialization as failure

**Locations:** go-libsodium `libsodium.go:24–27,50–58`; backup `internal/pack/pack.go:28,52`, `internal/metadatachain/chain.go:18,39`, `internal/backup/runtime.go:736`.

`Init` reads/writes a global Boolean without synchronization. Concurrent first callers can both enter `sodium_init`; its already-initialized return value is successful, but the wrapper panics on every nonzero result.

**Reproduced:** 32 simultaneous actual `Init` calls in a fresh process produce a Go race report and `failed to init sodium` panics. The current serial CLI is not shown to hit this schedule, but the shared library's public initializer is unsafe. Separate `sync.Once` instances in different backup packages do not provide library-wide exclusion.

**Required action:** own initialization once inside go-libsodium and correctly distinguish native failure from successful prior initialization. Remove redundant caller-owned initialization guards when that boundary is reliable; do not scatter more local locks across applications.

**Regression:** `TestReviewConcurrentInit` with `-race`.

### 8. Medium — Trusted configuration and CA validation can block forever before rejecting a FIFO

**Locations:** backup `internal/localconfig/config.go:34–50`, `internal/objectstore/client.go:483–493`.

Both readers use blocking `O_RDONLY|O_NOFOLLOW` and only inspect the file type after opening. Opening a FIFO with no writer blocks before either regular-file check or size bound runs. A typo or damaged local setup can hang command startup rather than return the promised bounded-file error.

**Reproduced:** both production readers remain blocked until a writer is deliberately connected, then reject the FIFO. The probes release the blocked reads before cleanup. This is a local configuration robustness defect, not a remote credential-redirection exploit.

**Required action:** use nonblocking, no-follow opens followed by descriptor type/mode/size validation, as the durable store and shared secret-file reader already do. Audit the same pattern in `runtime.openStaged` rather than assuming a no-follow flag alone establishes a regular file.

**Regressions:** `TestReviewTrustedConfigRejectsFIFOWithoutBlocking`, `TestReviewTrustedCARejectsFIFOWithoutBlocking`.

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
