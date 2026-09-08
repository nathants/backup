#!/usr/bin/env bash
# Separate Git-primary gate: never reuse object-mirror contract credentials.
set +x
set -euo pipefail
umask 077
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${LIBAWS_TEST_ACCOUNT:?guarded scratch account required}"
: "${AWS_ACCESS_KEY_ID:?explicit scratch credentials required}"
: "${AWS_SECRET_ACCESS_KEY:?explicit scratch credentials required}"
: "${GIT_REMOTE_AWS_TEST_OLD_BINARY:?independently built pre-keychain helper required}"
region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
[[ $LIBAWS_TEST_ACCOUNT =~ ^[0-9]{12}$ && $region =~ ^[a-z0-9-]+$ ]] || {
  echo 'invalid account guard or missing region' >&2; exit 1;
}
for tool in aws libaws go git python3 timeout; do
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
# Fail before provisioning if the exact independent old artifact is unavailable.
(cd "$repo/../git-remote-aws"; GOFLAGS= go test -count=1 -run '^TestKeyCompatibilitySelectedArtifact$' .)

if [[ -n ${BACKUP_CONTRACT_EVIDENCE_DIR:-} ]]; then
  mkdir -p -- "$BACKUP_CONTRACT_EVIDENCE_DIR"
  workspace=$(mktemp -d "$BACKUP_CONTRACT_EVIDENCE_DIR/git-primary.XXXXXXXX")
else
  workspace=$(mktemp -d "${TMPDIR:-/tmp}/backup-git-primary.XXXXXXXX")
fi
name="backup-git-test-$(tr -d '-' </proc/sys/kernel/random/uuid)"
printf '%s\n' "$name" > "$workspace/resource"
echo "Git-primary scratch bucket/table: $name; evidence: $workspace"
# Establish absence in the guarded account before recording create intent.
aws_call s3api list-buckets --output json > "$workspace/buckets-before.json"
aws_call dynamodb list-tables --output json > "$workspace/tables-before.json"
python3 -I - "$workspace" "$name" <<'PY'
import json, pathlib, sys
root, name = pathlib.Path(sys.argv[1]), sys.argv[2]
if (name in [x['Name'] for x in json.loads((root/'buckets-before.json').read_text())['Buckets']]
        or name in json.loads((root/'tables-before.json').read_text())['TableNames']):
    sys.exit('refusing to reuse an existing scratch resource')
PY
bucket_requested=false
table_requested=false
cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  # Inventory proves ownership/absence even after a lost create response.
  if $bucket_requested; then
    if aws_call s3api list-buckets --query "Buckets[?Name=='$name'].Name" --output text > "$workspace/bucket-owned"; then
      if [[ -s $workspace/bucket-owned ]]; then
        timeout --kill-after=10s 5m aws s3 rm "s3://$name/" --recursive > "$workspace/bucket-cleanup.log" 2>&1 &&
          aws_call s3api delete-bucket --bucket "$name" >> "$workspace/bucket-cleanup.log" 2>&1 || status=1
      fi
    else status=1; fi
  fi
  if $table_requested; then
    if aws_call dynamodb list-tables --query "TableNames[?@=='$name']" --output text > "$workspace/table-owned"; then
      if [[ -s $workspace/table-owned ]]; then
        aws_call dynamodb delete-table --table-name "$name" > "$workspace/table-cleanup.log" 2>&1 &&
          aws_call dynamodb wait table-not-exists --table-name "$name" >> "$workspace/table-cleanup.log" 2>&1 || status=1
      fi
    else status=1; fi
  fi
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
bucket_requested=true
args=(s3api create-bucket --bucket "$name")
if [[ $region != us-east-1 ]]; then args+=(--create-bucket-configuration "LocationConstraint=$region"); fi
aws_call "${args[@]}" > "$workspace/bucket-create.json"
table_requested=true
aws_call dynamodb create-table --table-name "$name" --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=id,AttributeType=S --key-schema AttributeName=id,KeyType=HASH > "$workspace/table-create.json"
aws_call dynamodb wait table-exists --table-name "$name"
export GIT_REMOTE_AWS_TEST_ACCOUNT=$LIBAWS_TEST_ACCOUNT GIT_REMOTE_AWS_TEST_BUCKET=$name GIT_REMOTE_AWS_TEST_TABLE=$name
for mode in normal race; do
  flags=''
  if [[ $mode == race ]]; then flags=-race; fi
  echo "Git-primary contract: $mode"
  (cd "$repo/../git-remote-aws"; GOFLAGS=$flags timeout --kill-after=30s 35m go test -count=1 -timeout=30m -v ./...) \
    > "$workspace/helper-$mode.log" 2>&1 || { tail -40 "$workspace/helper-$mode.log"; exit 1; }
  grep -q '^--- PASS: TestStoredDataCompatibilityAndRotation ' "$workspace/helper-$mode.log" || { echo 'old-data contract did not run' >&2; exit 1; }
  (cd "$repo"; BACKUP_GIT_REMOTE_CONTRACT=1 GOFLAGS=$flags timeout --kill-after=30s 35m go test -count=1 -timeout=30m -v -run '^TestAWSGitRemoteKeychains$' ./integration) \
    > "$workspace/backup-$mode.log" 2>&1 || { tail -40 "$workspace/backup-$mode.log"; exit 1; }
  grep -q '^--- PASS: TestAWSGitRemoteKeychains ' "$workspace/backup-$mode.log" || { echo 'backup Git-primary contract did not run' >&2; exit 1; }
done
echo 'Git-primary contracts passed; cleaning scratch resources.'
