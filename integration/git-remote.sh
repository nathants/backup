#!/usr/bin/env bash
# Separate Git-primary gate: never reuse object-mirror contract credentials.
set +x
set -euo pipefail
umask 077
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${LIBAWS_TEST_ACCOUNT:?guarded scratch account required}"
: "${AWS_ACCESS_KEY_ID:?explicit scratch credentials required}"
: "${AWS_SECRET_ACCESS_KEY:?explicit scratch credentials required}"
region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
[[ $LIBAWS_TEST_ACCOUNT =~ ^[0-9]{12}$ && $region =~ ^[a-z0-9-]+$ ]] || {
  echo 'invalid account guard or missing region' >&2; exit 1;
}
for tool in aws libaws go git timeout; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
# Pin provider routing; the tests intentionally receive scratch account access.
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case $name in AWS_ENDPOINT_URL | AWS_ENDPOINT_URL_*) unset "$name" ;; esac
done < <(env -0)
unset AWS_PROFILE AWS_DEFAULT_PROFILE AWS_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
unset GIT_REMOTE_AWS_PUBLICKEY GIT_REMOTE_AWS_SECRETKEY GIT_REMOTE_AWS_SECRETKEY_FILE GIT_REMOTE_AWS_SECRETKEY_CMD
export AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true
export AWS_REGION=$region AWS_DEFAULT_REGION=$region AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
export AWS_USE_FIPS_ENDPOINT=false AWS_USE_DUALSTACK_ENDPOINT=false AWS_PAGER=''
aws_call() { timeout --kill-after=10s 2m aws "$@"; }
[[ $(aws_call sts get-caller-identity --query Account --output text) == "$LIBAWS_TEST_ACCOUNT" ]] || {
  echo 'wrong scratch account' >&2; exit 1;
}
# Fail before creating resources if the sibling helper checkout does not build.
(cd "$repo/../git-remote-aws"; GOFLAGS= go build -o /dev/null .)
helper_revision=$(git -C "$repo/../git-remote-aws" rev-parse HEAD)
helper_status=$(git -C "$repo/../git-remote-aws" status --porcelain)
[[ -z $helper_status ]] || { echo 'Git-primary acceptance requires a clean helper checkout' >&2; exit 1; }
echo "git-remote-aws helper: $helper_revision"

if [[ -n ${BACKUP_CONTRACT_EVIDENCE_DIR:-} ]]; then
  mkdir -p -- "$BACKUP_CONTRACT_EVIDENCE_DIR"
  workspace=$(mktemp -d "$BACKUP_CONTRACT_EVIDENCE_DIR/git-primary.XXXXXXXX")
else
  workspace=$(mktemp -d "${TMPDIR:-/tmp}/backup-git-primary.XXXXXXXX")
fi
printf '%s\n' "$helper_revision" > "$workspace/helper-revision"
echo "Git-primary evidence: $workspace"
resources=()
contract_pid=''

inventory_bucket() { aws_call s3api list-buckets --query "Buckets[?Name=='$1'].Name" --output text; }
inventory_table() { aws_call dynamodb list-tables --query "TableNames[?@=='$1']" --output text; }

cleanup_resource() {
  local name=$1 failed=0 owned
  # Creation may have succeeded even when the helper returned no response.
  # Only names absent before create intent and now owned by this account qualify.
  if inventory_bucket "$name" > "$workspace/$name.bucket-owned"; then
    owned=$(< "$workspace/$name.bucket-owned")
    if [[ $owned == "$name" ]]; then
      timeout --kill-after=10s 5m libaws s3-rm-bucket "$name" > "$workspace/$name.bucket-cleanup.log" 2>&1 &&
        aws_call s3api wait bucket-not-exists --bucket "$name" --expected-bucket-owner "$LIBAWS_TEST_ACCOUNT" >> "$workspace/$name.bucket-cleanup.log" 2>&1 || failed=1
    elif [[ -n $owned ]]; then
      echo "unexpected bucket ownership inventory: $name" >&2
      failed=1
    fi
  else failed=1; fi
  # Attempt the table independently, including after bucket errors/timeouts.
  if inventory_table "$name" > "$workspace/$name.table-owned"; then
    owned=$(< "$workspace/$name.table-owned")
    if [[ $owned == "$name" ]]; then
      aws_call dynamodb delete-table --table-name "$name" > "$workspace/$name.table-cleanup.log" 2>&1 &&
        aws_call dynamodb wait table-not-exists --table-name "$name" >> "$workspace/$name.table-cleanup.log" 2>&1 || failed=1
    elif [[ -n $owned ]]; then
      echo "unexpected table ownership inventory: $name" >&2
      failed=1
    fi
  else failed=1; fi
  return "$failed"
}

cleanup() {
  local status=$? name
  trap - EXIT
  trap ':' INT TERM
  if [[ -n $contract_pid ]]; then
    # GNU timeout forwards TERM and enforces --kill-after for an unresponsive
    # child. Drain that group before deleting anything it could still publish.
    kill -TERM "$contract_pid" 2>/dev/null || true
    wait "$contract_pid" 2>/dev/null || true
    kill -KILL -- "-$contract_pid" 2>/dev/null || true
  fi
  for name in "${resources[@]}"; do
    if ! cleanup_resource "$name"; then
      echo "Git-primary cleanup failed: $name" >&2
      if [[ $status == 0 ]]; then status=1; fi
    fi
  done
  if [[ $status == 0 && -z ${BACKUP_CONTRACT_EVIDENCE_DIR:-} ]]; then
    rm -rf -- "$workspace"
  else
    echo "Retained Git-primary evidence: $workspace" >&2
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for mode in normal race; do
  name="backup-git-test-$(tr -d '-' </proc/sys/kernel/random/uuid)"
  echo "Git-primary contract: $mode; scratch bucket/table: $name"
  inventory_bucket "$name" > "$workspace/$name.buckets-before"
  inventory_table "$name" > "$workspace/$name.tables-before"
  if [[ -n $(< "$workspace/$name.buckets-before") || -n $(< "$workspace/$name.tables-before") ]]; then
    echo 'refusing to reuse an existing scratch resource' >&2
    exit 1
  fi
  # Record intent before the helper is allowed to create either resource.
  printf '%s\t%s\n' "$mode" "$name" >> "$workspace/resources.tsv"
  resources+=("$name")
  flags=''
  if [[ $mode == race ]]; then flags=-race; fi
  # Defer interruption until the child's identity is available to cleanup.
  signal_status=0
  trap 'signal_status=130' INT
  trap 'signal_status=143' TERM
  (cd "$repo"; BACKUP_GIT_REMOTE_CONTRACT=1 BACKUP_GIT_REMOTE_RESOURCE=$name GOFLAGS=$flags exec timeout --kill-after=30s 35m go test -count=1 -timeout=30m -v -run '^TestAWSGitRemoteKeychains$' ./integration) \
    > "$workspace/backup-$mode.log" 2>&1 &
  contract_pid=$!
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ $signal_status != 0 ]]; then exit "$signal_status"; fi
  test_status=0
  wait "$contract_pid" || test_status=$?
  # A Go test timeout can leave child helpers after the test process exits.
  kill -KILL -- "-$contract_pid" 2>/dev/null || true
  contract_pid=''
  if [[ $test_status != 0 ]]; then tail -40 "$workspace/backup-$mode.log"; exit "$test_status"; fi
  grep -q '^--- PASS: TestAWSGitRemoteKeychains ' "$workspace/backup-$mode.log" || { echo 'backup Git-primary contract did not run' >&2; exit 1; }
done
current_revision=$(git -C "$repo/../git-remote-aws" rev-parse HEAD)
current_status=$(git -C "$repo/../git-remote-aws" status --porcelain)
[[ $current_revision == "$helper_revision" && -z $current_status ]] || {
  echo 'helper checkout changed during acceptance' >&2; exit 1;
}
echo 'Git-primary contracts passed; cleaning scratch resources.'
