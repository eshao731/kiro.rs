#!/usr/bin/env bash
# Deploy one prebuilt kiro.rs binary to an explicitly selected production node.
#
# Examples:
#   DEPLOY_NODE=A LOCAL_BINARY=/path/to/kiro2api ./scripts/deploy-production.sh
#   DEPLOY_NODE=B LOCAL_BINARY=/path/to/kiro2api ./scripts/deploy-production.sh
#
# This script is binary-only by design. config.json, credentials.json, client
# keys, usage logs, and caches are production state and must not be overwritten.

set -Eeuo pipefail

DEPLOY_NODE="${DEPLOY_NODE:-}"
LOCAL_BINARY="${LOCAL_BINARY:-}"
SERVICE_NAME="${SERVICE_NAME:-kiro2api}"
REMOTE_BINARY="${REMOTE_BINARY:-/opt/kiro2api/kiro2api}"

case "${DEPLOY_NODE}" in
  A)
    DEPLOY_HOST="${DEPLOY_HOST:-root@15.235.42.210}"
    DEPLOY_PORT="${DEPLOY_PORT:-22}"
    ;;
  B)
    DEPLOY_HOST="${DEPLOY_HOST:-root@96.9.225.103}"
    DEPLOY_PORT="${DEPLOY_PORT:-22}"
    ;;
  *)
    echo "DEPLOY_NODE must be A or B; refusing an ambiguous production deploy." >&2
    exit 2
    ;;
esac

if [[ -z "${LOCAL_BINARY}" || ! -f "${LOCAL_BINARY}" ]]; then
  echo "LOCAL_BINARY must point to a prebuilt linux/amd64 kiro.rs binary." >&2
  exit 2
fi

if ! file "${LOCAL_BINARY}" | grep -Eq 'ELF 64-bit.*x86-64'; then
  echo "LOCAL_BINARY is not an x86-64 Linux ELF binary." >&2
  exit 2
fi

local_sha="$(shasum -a 256 "${LOCAL_BINARY}" | awk '{print $1}')"
echo "Deploying Kiro-${DEPLOY_NODE} to ${DEPLOY_HOST}:${REMOTE_BINARY}"
echo "Local SHA-256: ${local_sha}"

scp -P "${DEPLOY_PORT}" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  "${LOCAL_BINARY}" "${DEPLOY_HOST}:${REMOTE_BINARY}.next"

ssh -p "${DEPLOY_PORT}" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=accept-new \
  "${DEPLOY_HOST}" \
  "REMOTE_BINARY=$(printf '%q' "${REMOTE_BINARY}") SERVICE_NAME=$(printf '%q' "${SERVICE_NAME}") EXPECTED_SHA=$(printf '%q' "${local_sha}") bash -s" <<'REMOTE'
set -Eeuo pipefail

# Refuse deployment if the runtime state is incomplete. Recreating config files
# would generate new API/admin keys and an empty credential list.
test -f /opt/kiro2api/config.json
test -f /opt/kiro2api/credentials.json
test -f /opt/kiro2api/client_api_keys.json

python3 - <<'PY'
import json

config = json.load(open('/opt/kiro2api/config.json'))
assert config.get('host') == '127.0.0.1', 'Kiro must remain loopback-only'
assert int(config.get('port')) == 8990, 'unexpected Kiro listener port'
PY

if [[ -f "${REMOTE_BINARY}" ]]; then
  cp -a "${REMOTE_BINARY}" "${REMOTE_BINARY}.previous"
  cp -a "${REMOTE_BINARY}" "${REMOTE_BINARY}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
  # Bound release history so routine deployments cannot grow disk usage without
  # limit. The deterministic .previous file is kept separately for auto-rollback.
  ls -1t "${REMOTE_BINARY}".bak-* 2>/dev/null | tail -n +6 | xargs -r rm -f --
fi
install -o kiro2api -g kiro2api -m 0750 "${REMOTE_BINARY}.next" "${REMOTE_BINARY}"
rm -f "${REMOTE_BINARY}.next"

remote_sha="$(sha256sum "${REMOTE_BINARY}" | awk '{print $1}')"
[[ "${remote_sha}" == "${EXPECTED_SHA}" ]]

systemctl restart "${SERVICE_NAME}"
for attempt in $(seq 1 20); do
  if systemctl is-active --quiet "${SERVICE_NAME}" && curl -fsS http://127.0.0.1:8990/admin >/dev/null; then
    echo "Kiro deployment healthy; runtime credentials were preserved."
    exit 0
  fi
  sleep 1
done

systemctl --no-pager --full status "${SERVICE_NAME}" >&2 || true
journalctl -u "${SERVICE_NAME}" -n 80 --no-pager >&2 || true

if [[ -f "${REMOTE_BINARY}.previous" ]]; then
  echo "Health check failed; restoring the previous Kiro binary." >&2
  install -o kiro2api -g kiro2api -m 0750 "${REMOTE_BINARY}.previous" "${REMOTE_BINARY}"
  systemctl restart "${SERVICE_NAME}"
  for attempt in $(seq 1 20); do
    if systemctl is-active --quiet "${SERVICE_NAME}" && curl -fsS http://127.0.0.1:8990/admin >/dev/null; then
      echo "Previous Kiro binary restored and healthy." >&2
      exit 1
    fi
    sleep 1
  done
  echo "Automatic rollback also failed; manual intervention is required." >&2
fi
exit 1
REMOTE
