# AWS Git-primary release gate

Run this **in addition to** `make integration` before release. The object-mirror
contract and Git-primary contract have different permissions and resources; neither
substitutes for the other. Do not give the immutable mirror credential DynamoDB or
broader S3 permissions to make this test work.

The checked-in `integration/git-remote.sh` provisions one fresh private, unversioned
scratch S3 bucket and one DynamoDB table under a random `backup-git-test-` name.
It runs the complete sibling git-remote-aws test suite, then the real backup CLI
against that primary and a local TLS object server. It repeats both with
`GOFLAGS=-race`, instrumenting newly built child binaries as well as test processes.
The independently retained old helper is never rebuilt or modified. Explicit PASS
checks prevent the old-data and cross-repository contracts from silently skipping.

Requirements:

1. The sibling source checkouts, Go/libsodium and normal project check tools.
2. AWS CLI, libaws, Git, GNU timeout, and Python 3.8 or newer (also needed by the
   cloud-free executable/PTY secret-loader regressions). Nothing is auto-installed.
3. Explicit scratch-account AWS access-key environment credentials, an optional
   session token, region, and an independent `LIBAWS_TEST_ACCOUNT` guard. The runner
   verifies STS identity and disables ambient endpoint overrides/profile fallback.
4. `GIT_REMOTE_AWS_TEST_OLD_BINARY` pointing to an independently built pre-keychain
   git-remote-aws executable using its original public dependency graph, including
   go-libsodium `v0.0.0-20260502104057-4e1a79aae4f3` without replacement. Prepare this
   separately from reviewed historical source; the runner never downloads or
   installs it. Its build metadata is checked before resource provisioning.

```sh
# Load administrator credentials for the dedicated scratch account privately.
export LIBAWS_TEST_ACCOUNT=123456789012
export AWS_REGION=ap-southeast-1
export GIT_REMOTE_AWS_TEST_OLD_BINARY=/private/pre-keychain/git-remote-aws
export BACKUP_CONTRACT_EVIDENCE_DIR="$HOME/.config/backup/contracts"
make integration-git-remote
```

The Make target first runs cloud-free `make check`. For a focused rerun after that
passes, execute `./integration/git-remote.sh` with the same environment. The runner
prints the exact bucket/table name and evidence directory before mutation. Test
logs and resource inventories are private; do not publish them indiscriminately.

The runner establishes resource absence in the guarded account before create
intent and cleans up its bucket's objects and table after success or failure,
including ambiguous create outcomes through fresh ownership inventory. Cleanup
errors fail the gate and retain evidence. A host crash/SIGKILL can bypass traps:
use the printed resource name and preserved inventories for targeted cleanup,
never a broad deletion of similarly named resources. Independent account inventory
should confirm removal after the gate. These are disposable, unversioned test
resources, not immutable production mirrors or retained ransomware probes.

A successful test proves real backup/helper interoperability, committed recipient
policy, rotation, mixed-generation clone/restore, and old SHA-1/SHA-256 full and
incremental ciphertext readability. It does not accept a production deployment or
remove the separate first-backup gates.
