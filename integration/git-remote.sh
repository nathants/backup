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
[[ $(timeout --kill-after=10s 2m aws sts get-caller-identity --query Account --output text) == "$LIBAWS_TEST_ACCOUNT" ]] || {
  echo 'wrong scratch account' >&2; exit 1;
}
# Fail before creating resources if the sibling helper checkout does not build.
(cd "$repo/../git-remote-aws"; GOFLAGS= go build -o /dev/null .)
echo "git-remote-aws helper: $(git -C "$repo/../git-remote-aws" describe --always --dirty)"

if [[ -n ${BACKUP_CONTRACT_EVIDENCE_DIR:-} ]]; then
  mkdir -p -- "$BACKUP_CONTRACT_EVIDENCE_DIR"
  workspace=$(mktemp -d "$BACKUP_CONTRACT_EVIDENCE_DIR/git-primary.XXXXXXXX")
else
  workspace=$(mktemp -d "${TMPDIR:-/tmp}/backup-git-primary.XXXXXXXX")
fi
echo "Git-primary evidence: $workspace"
cleanup() {
  status=$?
  trap - EXIT INT TERM
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
# Each run creates and deletes its own scratch bucket and table.
for mode in normal race; do
  flags=''
  if [[ $mode == race ]]; then flags=-race; fi
  echo "Git-primary contract: $mode"
  (cd "$repo"; BACKUP_GIT_REMOTE_CONTRACT=1 GOFLAGS=$flags timeout --kill-after=30s 35m go test -count=1 -timeout=30m -v -run '^TestAWSGitRemoteKeychains$' ./integration) \
    > "$workspace/backup-$mode.log" 2>&1 || { tail -40 "$workspace/backup-$mode.log"; exit 1; }
  grep -q '^--- PASS: TestAWSGitRemoteKeychains ' "$workspace/backup-$mode.log" || { echo 'backup Git-primary contract did not run' >&2; exit 1; }
done
echo 'Git-primary contracts passed.'
