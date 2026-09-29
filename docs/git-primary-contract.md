# AWS Git-primary release gate

Run this **in addition to** `make integration` before release. The object-mirror
contract and Git-primary contract have different permissions and resources; neither
substitutes for the other. Do not give the immutable mirror credential DynamoDB or
broader S3 permissions to make this test work.

The checked-in `integration/git-remote.sh` runs the real backup CLI against an AWS
Git primary and a local TLS object server, with a helper built from the clean
sibling `../git-remote-aws` checkout. The runner records its full commit ID in
`helper-revision` and rejects checkout changes during the run. Keep that checkout
exclusively controlled while testing. Each test run creates one fresh private
scratch S3 bucket and one DynamoDB table under a random `backup-git-test-` name
through the helper's `ensure=y` setup. The runner repeats the run with
`GOFLAGS=-race`, instrumenting newly built child binaries as well as test processes.
An explicit PASS check prevents the contract from silently skipping.

## Separate helper acceptance

Before production use, also require the helper's own complete live AWS gate to
pass at the **same clean helper commit** recorded by this gate. Retain its command,
commit ID, and complete passing log alongside the backup gate's evidence. Follow
the helper checkout's validation instructions; its current live gate is
`GOTOOLCHAIN=local GOFLAGS=-race go test -count=1 -timeout=60m ./...`, with
`GIT_REMOTE_AWS_TEST_ACCOUNT` set to the independently known scratch account.
Run the gates sequentially, not concurrently in one scratch account. Historical
fixture builds have separate prerequisites governed by that project.

This backup gate tests interoperability, not the helper's entire behavior. Lease,
namespace, failure, and historical-readability contracts remain in git-remote-aws;
this clean-break project has no older helper data. A backup-gate PASS alone does
not qualify the helper for deployment. Any helper change invalidates the pairing
of the two gates' evidence.

## Running the backup gate

Requirements:

1. The sibling source checkouts, Go/libsodium and normal project check tools.
2. AWS CLI, libaws, Git, GNU timeout, and Python 3.8 or newer. Nothing is
   auto-installed. Cloud-free process-lifecycle checks build and execute the real
   sibling helper and Git; provider behavior is tested only by the live gate.
3. Explicit scratch-account AWS access-key environment credentials, an optional
   session token, region, and an independent `LIBAWS_TEST_ACCOUNT` guard. The runner
   verifies STS identity and disables ambient endpoint overrides/profile fallback.
   Its administrative credential needs account bucket/table inventory, helper
   setup, permanent S3 version deletion, bucket-policy deletion, bucket deletion,
   and table deletion permissions. Never use production credentials.

```sh
# Load administrator credentials for the dedicated scratch account privately.
export LIBAWS_TEST_ACCOUNT=123456789012
export AWS_REGION=ap-southeast-1
export BACKUP_CONTRACT_EVIDENCE_DIR="$HOME/.config/backup/contracts"
make integration-git-remote
```

The Make target first runs cloud-free `make check`. For a focused rerun after that
passes, execute `./integration/git-remote.sh` with the same environment. Do not run
the live Go test directly: the runner owns its resource guard and cleanup.

The runner prints its evidence directory and exact bucket/table names. It refuses
names already present in the guarded account and fails closed on inventory errors.
Only after both absence checks does it record create intent in `resources.tsv`
and pass the name to the helper test. Setup is retried only while the bucket is
still absent, because the helper never retries an uncertain CreateBucket.

A Linux child subreaper drains remaining test descendants, including those that
created separate process groups or sessions, after success, failure, test timeout,
SIGINT, or SIGTERM. It sends TERM, escalates to KILL after 30 seconds, and allows
10 more seconds to confirm exit. Without confirmed drainage the gate fails and
retains resources for operator inspection rather than racing a surviving writer.

Once descendants have exited, runner cleanup inventories and permanently deletes
its resources, including every S3 object version and delete marker. Each cleanup
command has a bounded deadline; bucket cleanup failure does not prevent table
cleanup or cleanup of the other test run. Fresh ownership inventory also covers
ambiguous creation outcomes. Cleanup errors fail the gate and retain evidence.
Test logs, inventories, and cleanup logs are private; do not publish them
indiscriminately.

A host crash or SIGKILL of the runner can still bypass cleanup. Use its retained
`resources.tsv` and inventories to inspect and delete only that run's exact bucket
and table names; never broadly delete similarly named resources. Independent account
inventory should confirm removal after the gate. These are disposable test resources,
not immutable production mirrors or retained ransomware probes.

A successful test proves real backup/helper interoperability, committed recipient
policy, rotation, and mixed-generation clone/restore. It does not accept a
production deployment or remove the separate first-backup gates.
