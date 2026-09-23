# Backup contributor contract

[Design and operations](docs/design.md) is the authoritative design agreed with
Admin. Read the relevant sections before changing a subsystem. Stop and discuss
material changes to settled design choices; unambiguous correctness, durability,
safety, and cleanup fixes do not need to be reopened.

This is a clean-break Go rewrite. There is no legacy backup data to migrate.
Prefer boring files and explicit invariants over new abstractions or compatibility.

## Essential invariants

1. Recoverability comes first. Published objects are immutable: repair relocates
   healthy bytes to new keys and never deletes or overwrites old objects.
2. Success requires the mandatory primary Git push and **one individual mirror**
   with the entire data catalog and metadata-bundle chain. A union of partial
   mirrors, existence checks, or conditional-write conflicts cannot prove success.
3. Metadata is a single linear, fast-forward-only SHA-256 Git history. Validate
   untrusted trees and transitions before materialization; never discard local
   edits to adopt a fetched tip. Canonical topology cannot redirect credentials:
   trusted local configuration must pin every destination before I/O.
4. Each repository has one authoritative writable checkout and operational ledger.
   Keep local locking and Git CAS defenses; do not invent distributed ownership.
   Durable staging, acknowledgements, and quarantine must survive retries/crashes.
5. Network mirrors enforce read/list/create-only access with one ordinary credential;
   administration stays off clients. Directly writable filesystem mirrors are an
   explicit ransomware-boundary exception, not equivalent protection.
6. Restore verifies all selected content before any publication, stays beneath the
   target through no-follow descriptor-relative operations, and never truncates
   an existing destination before verification. Destinations and local operational
   namespaces require exclusive operator control. Potentially malicious restore,
   recovery, and recovery listing require operator-enforced aggregate resource limits.

## Subsystem reading

- Metadata/configuration/history: [metadata rules](docs/design.md#metadata-files)
  and [trusted configuration](docs/design.md#build-and-trusted-local-configuration).
- Planning, capture, and resumability: [filesystem semantics](docs/design.md#filesystem-semantics)
  and [transaction protocol](docs/design.md#local-staging-and-transaction-protocol).
- Objects, mirrors, server, and repair: [pack format](docs/design.md#pack-and-object-format),
  [mirror chains](docs/design.md#mirrors-and-self-contained-metadata),
  [server contract](docs/design.md#production-backup-server), and
  [verification/repair](docs/design.md#verification-and-repair).
- Read [filesystem mirrors](docs/filesystem-mirrors.md) before configuring,
  modifying, or operating that backend; production storage is operator-controlled ext4.
- Read [key management](docs/key-management.md) before key generation/rotation or
  secret-source work. Shared key chains/encryption belong in go-libsodium; keygen
  belongs in git-remote-aws and must never receive repository `.publickeys` as a personal file.
- Restore/recovery: [restore safety](docs/design.md#restore-safety) and
  [recovery-to-restore runbook](docs/recovery-restore.md).
- Deployment/release: [testing contracts](docs/design.md#testing-requirements),
  [Git-primary gate](docs/git-primary-contract.md), and
  [first-backup gates](docs/design.md#release-and-first-backup-gates).

## Build and validation

Linux 5.8+, Go 1.27+, Git 2.36+ with SHA-256 support, and libsodium are required.
`make` or `make build` builds `./backup`. Use published dependencies pinned in
`go.mod`; remove temporary local replacements before committing published updates.

Use targeted tests while iterating. `make check` runs mandatory lint, coverage,
race, and vet checks without cloud access; missing linters fail closed.
`make fuzz` runs mutation campaigns. Integration and exact-production acceptance
are separate gates: passing local tests or ordinary uploads does not qualify a backend.
