#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
libaws=${LIBAWS:-libaws}
infra_source="$repo/infra.yaml"

for command in docker timeout mktemp cmp; do
  command -v "$command" >/dev/null || {
    echo "$command executable not found" >&2
    exit 1
  }
done
command -v "$libaws" >/dev/null || {
  echo "libaws executable not found: $libaws" >&2
  exit 1
}
timeout --foreground --kill-after=10s 30s docker info >/dev/null 2>&1 || {
  echo "docker daemon is unavailable" >&2
  exit 1
}
[[ -n ${LIBAWS_TEST_ACCOUNT:-} ]] || {
  echo "LIBAWS_TEST_ACCOUNT is required" >&2
  exit 1
}
region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
[[ -n $region ]] || {
  echo "AWS_REGION or AWS_DEFAULT_REGION is required" >&2
  exit 1
}

scrub_aws_endpoint_environment() {
  local entry name
  while IFS= read -r entry; do
    name=${entry%%=*}
    case $name in
      AWS_ENDPOINT_URL | AWS_ENDPOINT_URL_*) unset "$name" ;;
    esac
  done < <(env)
}

libaws_aws() (
  local duration=$1
  shift
  scrub_aws_endpoint_environment
  export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
  export AWS_USE_FIPS_ENDPOINT=false
  export AWS_USE_DUALSTACK_ENDPOINT=false
  timeout --foreground --kill-after=10s "$duration" "$libaws" "$@"
)

if ! account=$(libaws_aws 2m aws-account); then
  echo "could not determine the guarded AWS account" >&2
  exit 1
fi
[[ $account == "$LIBAWS_TEST_ACCOUNT" ]] || {
  echo "refusing AWS integration account $account; expected $LIBAWS_TEST_ACCOUNT" >&2
  exit 1
}

infra_snapshot=$(mktemp "${TMPDIR:-/tmp}/backup-infra.XXXXXXXX")
chmod 0600 "$infra_snapshot"
if ! cat -- "$infra_source" >"$infra_snapshot" || ! cmp -s -- "$infra_source" "$infra_snapshot"; then
  rm -f -- "$infra_snapshot"
  echo "could not take a stable snapshot of $infra_source" >&2
  exit 1
fi

suffix=$(tr -d '-' </proc/sys/kernel/random/uuid | cut -c1-8)
docker_run_id=$suffix
docker_server_image="backup-test:rewrite-$suffix"
docker_client_image="backup-test:integration-client-$suffix"
export BACKUP_DOCKER_RUN_ID=$docker_run_id
export BACKUP_DOCKER_SERVER_IMAGE=$docker_server_image
export BACKUP_DOCKER_CLIENT_IMAGE=$docker_client_image

cleanup_needed=false
infra_cleaned=true

bounded_docker() {
  local duration=$1
  shift
  timeout --foreground --kill-after=10s "$duration" docker "$@"
}

cleanup() {
  local status=$?
  local containers volumes image attempt
  trap - EXIT
  set +e

  unset BACKUP_AWS_CONTRACT_ACCESS_KEY BACKUP_AWS_CONTRACT_SECRET_KEY
  unset BACKUP_AWS_CONTRACT_SESSION_TOKEN

  if ! containers=$(bounded_docker 2m ps -aq --filter "label=backup.integration.run=$docker_run_id"); then
    echo "could not inventory this run's Docker containers" >&2
    status=1
  elif [[ -n $containers ]]; then
    mapfile -t container_ids <<<"$containers"
    if ! bounded_docker 2m rm -f "${container_ids[@]}" >/dev/null; then
      echo "could not remove this run's Docker containers" >&2
      status=1
    fi
  fi
  if ! volumes=$(bounded_docker 2m volume ls -q --filter "label=backup.integration.run=$docker_run_id"); then
    echo "could not inventory this run's Docker volumes" >&2
    status=1
  elif [[ -n $volumes ]]; then
    mapfile -t volume_names <<<"$volumes"
    if ! bounded_docker 2m volume rm -f "${volume_names[@]}" >/dev/null; then
      echo "could not remove this run's Docker volumes" >&2
      status=1
    fi
  fi
  for image in "$docker_server_image" "$docker_client_image"; do
    if bounded_docker 30s image inspect "$image" >/dev/null 2>&1 &&
      ! bounded_docker 2m image rm "$image" >/dev/null; then
      echo "could not remove Docker image tag $image" >&2
      status=1
    fi
  done

  if $cleanup_needed; then
    infra_cleaned=false
    for attempt in 1 2 3; do
      if libaws_aws 10m infra-rm "$infra_snapshot"; then
        infra_cleaned=true
        break
      fi
      if ((attempt < 3)); then
        echo "retrying infrastructure cleanup ($((attempt + 1))/3): $BACKUP_AWS_INFRASET" >&2
        sleep "$attempt"
      fi
    done
    if ! $infra_cleaned; then
      echo "infrastructure cleanup failed: $BACKUP_AWS_INFRASET" >&2
      echo "retained exact infrastructure snapshot: $infra_snapshot" >&2
      status=1
    fi
  fi
  if $infra_cleaned; then
    rm -f -- "$infra_snapshot"
  fi
  exit "$status"
}
trap cleanup EXIT

built=false
for attempt in 1 2 3; do
  if bounded_docker 30m build --progress=plain --build-context "go-libsodium=$repo/../go-libsodium" -t "$docker_server_image" "$repo" &&
    bounded_docker 30m build --progress=plain --build-context "go-libsodium=$repo/../go-libsodium" --target integration-client -t "$docker_client_image" "$repo"; then
    built=true
    break
  fi
  if ((attempt < 3)); then
    echo "retrying Docker integration build ($((attempt + 1))/3)" >&2
    sleep "$attempt"
  fi
done
$built || {
  echo "Docker integration build failed" >&2
  exit 1
}
export BACKUP_DOCKER_IMAGES_READY=1

base="backup-testing-${account}-$(date -u +%Y%m%d%H%M%S)-${suffix}"
export BACKUP_AWS_INFRASET=$base
export BACKUP_AWS_BUCKET=$base
export BACKUP_AWS_USER="${base}-client"

echo "AWS integration infrastructure: $base" >&2
cleanup_needed=true
if ! libaws_aws 15m infra-ensure "$infra_snapshot"; then
  echo "infrastructure ensure failed: $base" >&2
  exit 1
fi
if ! preview=$(libaws_aws 15m infra-ensure "$infra_snapshot" --preview 2>&1); then
  printf 'second infrastructure preview failed:\n%s\n' "$preview" >&2
  exit 1
fi
[[ -z $preview ]] || {
  printf 'second infra-ensure was not converged:\n%s\n' "$preview" >&2
  exit 1
}

bootstrap_key() {
  local user=$1 id_name=$2 secret_name=$3 output id secret
  if ! output=$(libaws_aws 2m iam-ensure-user-api-key "$user"); then
    echo "failed to bootstrap one access key for $user" >&2
    return 1
  fi
  id=$(awk -F': ' '$1 == "access key id" { print $2 }' <<<"$output")
  secret=$(awk -F': ' '$1 == "access key secret" { print $2 }' <<<"$output")
  [[ -n $id && -n $secret ]] || {
    echo "failed to bootstrap one access key for $user" >&2
    return 1
  }
  printf -v "$id_name" '%s' "$id"
  printf -v "$secret_name" '%s' "$secret"
}

generated_libaws() (
  local id=$1 secret=$2 duration=$3
  shift 3
  export AWS_ACCESS_KEY_ID=$id
  export AWS_SECRET_ACCESS_KEY=$secret
  export AWS_SESSION_TOKEN=
  unset AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SECURITY_TOKEN
  unset AWS_PROFILE AWS_DEFAULT_PROFILE
  unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME
  unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
  unset AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
  export AWS_CONFIG_FILE=/dev/null
  export AWS_SHARED_CREDENTIALS_FILE=/dev/null
  export AWS_EC2_METADATA_DISABLED=true
  export LOGGING=no
  libaws_aws "$duration" "$@"
)

wait_for_key() {
  local id=$1 secret=$2 label=$3 observed deadline
  deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    if observed=$(generated_libaws "$id" "$secret" 10s aws-account 2>/dev/null) && [[ $observed == "$account" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "$label access key did not become usable in the guarded account" >&2
  return 1
}

bootstrap_key "$BACKUP_AWS_USER" client_id client_secret
wait_for_key "$client_id" "$client_secret" client

unset BACKUP_AWS_CONTRACT_ENDPOINT BACKUP_AWS_CONTRACT_PREFIX
unset BACKUP_AWS_CONTRACT_SESSION_TOKEN
export BACKUP_AWS_CONTRACT=1
export BACKUP_AWS_CONTRACT_BUCKET=$BACKUP_AWS_BUCKET
export BACKUP_AWS_CONTRACT_REGION=$region
export BACKUP_AWS_CONTRACT_USER=$BACKUP_AWS_USER
export BACKUP_AWS_CONTRACT_ACCESS_KEY=$client_id
export BACKUP_AWS_CONTRACT_SECRET_KEY=$client_secret
unset client_id client_secret

run_tests() (
  scrub_aws_endpoint_environment
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  unset AWS_ACCESS_KEY AWS_SECRET_KEY AWS_SECURITY_TOKEN
  unset AWS_PROFILE AWS_DEFAULT_PROFILE
  unset AWS_REGION AWS_DEFAULT_REGION AWS_CA_BUNDLE
  unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_ROLE_SESSION_NAME
  unset AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
  unset AWS_CONTAINER_AUTHORIZATION_TOKEN AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
  export AWS_CONFIG_FILE=/dev/null
  export AWS_SHARED_CREDENTIALS_FILE=/dev/null
  export AWS_EC2_METADATA_DISABLED=true
  export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
  export AWS_USE_FIPS_ENDPOINT=false
  export AWS_USE_DUALSTACK_ENDPOINT=false
  export BACKUP_DOCKER_TEST=1
  timeout --foreground --kill-after=30s 35m go test "$@" ./integration
)

(
  cd "$repo"
  run_tests -count=1 -timeout=30m -v
  run_tests -count=1 -race -timeout=30m -v
)
