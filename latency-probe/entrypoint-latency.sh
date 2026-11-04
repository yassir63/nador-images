#!/usr/bin/env bash
set -euo pipefail

IFACE="${IFACE:-n3}"
LATENCY_MODE="${LATENCY_MODE:-BOTH}"
PROBE_ROLE="${PROBE_ROLE:-gnb}"
MATCH_DEBUG="${MATCH_DEBUG:-0}"
PACKET_PAIRING="${PACKET_PAIRING:-${PACKET_CORRELATION:-0}}"
PACKET_PAIRER_HOST="${PACKET_PAIRER_HOST:-${PACKET_COLLECTOR_HOST:-}}"
PACKET_PAIRER_PORT="${PACKET_PAIRER_PORT:-${PACKET_COLLECTOR_PORT:-9201}}"
UE_MAP_FP="${UE_MAP_FP:-none}"
EXPORTER_PORT="${EXPORTER_PORT:-9100}"
EXPORTER_PATH="${EXPORTER_PATH:-/latency}"
PRIO="${PRIO:-1}"
HANDLE="${HANDLE:-1}"
TEIDS="${TEIDS:-}"
CLEANUP_TIMEOUT="${CLEANUP_TIMEOUT:-5}"

echo "[entrypoint] IFACE=${IFACE}"
echo "[entrypoint] LATENCY_MODE=${LATENCY_MODE}"
echo "[entrypoint] PROBE_ROLE=${PROBE_ROLE}"
echo "[entrypoint] MATCH_DEBUG=${MATCH_DEBUG}"
echo "[entrypoint] PACKET_PAIRING=${PACKET_PAIRING}"
echo "[entrypoint] PACKET_PAIRER_HOST=${PACKET_PAIRER_HOST:-unset}"
echo "[entrypoint] PACKET_PAIRER_PORT=${PACKET_PAIRER_PORT}"
echo "[entrypoint] UE_MAP_FP=${UE_MAP_FP}"
echo "[entrypoint] EXPORTER_PORT=${EXPORTER_PORT}"
echo "[entrypoint] EXPORTER_PATH=${EXPORTER_PATH}"
echo "[entrypoint] PRIO=${PRIO}"
echo "[entrypoint] HANDLE=${HANDLE}"
echo "[entrypoint] CLEANUP_TIMEOUT=${CLEANUP_TIMEOUT}"
echo "[entrypoint] TEIDS=${TEIDS}"

tc qdisc show dev "${IFACE}" | grep -q clsact || tc qdisc add dev "${IFACE}" clsact

filter_exists() {
  local direction="$1"
  local handle="$2"
  local handle_hex

  printf -v handle_hex "%x" "${handle}"
  tc filter show dev "${IFACE}" "${direction}" 2>/dev/null | grep -Eq \
    "(^|[[:space:]])(pref|prio)[[:space:]]+${PRIO}([[:space:]]|$)|(^|[[:space:]])handle[[:space:]]+(0x${handle_hex}|${handle})([[:space:]]|$)"
}

EGRESS_HANDLE=$((HANDLE + 1))
if filter_exists ingress "${HANDLE}"; then
  echo "[entrypoint] ERROR: existing ingress TC filter on ${IFACE} for prio=${PRIO} or handle=${HANDLE}" >&2
  exit 1
fi

if filter_exists egress "${EGRESS_HANDLE}"; then
  echo "[entrypoint] ERROR: existing egress TC filter on ${IFACE} for prio=${PRIO} or handle=${EGRESS_HANDLE}" >&2
  exit 1
fi

BPF_PID=""
EXPORTER_PID=""
CLEANED_UP=0

stop_process() {
  local pid="$1"
  local label="$2"
  local waited=0

  if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
    return
  fi

  echo "[entrypoint] Stopping ${label} (pid=${pid})..."
  kill -TERM "${pid}" 2>/dev/null || true

  while kill -0 "${pid}" 2>/dev/null && [ "${waited}" -lt "${CLEANUP_TIMEOUT}" ]; do
    sleep 1
    waited=$((waited + 1))
  done

  if kill -0 "${pid}" 2>/dev/null; then
    echo "[entrypoint] ${label} did not stop after ${CLEANUP_TIMEOUT}s; sending KILL."
    kill -KILL "${pid}" 2>/dev/null || true
  fi

  wait "${pid}" 2>/dev/null || true
}

delete_owned_filters() {
  local attempt

  for attempt in 1 2 3; do
    tc filter del dev "${IFACE}" ingress prio "${PRIO}" 2>/dev/null || true
    tc filter del dev "${IFACE}" egress prio "${PRIO}" 2>/dev/null || true
    tc filter del dev "${IFACE}" ingress handle "${HANDLE}" 2>/dev/null || true
    tc filter del dev "${IFACE}" egress handle "${EGRESS_HANDLE}" 2>/dev/null || true

    if ! filter_exists ingress "${HANDLE}" && ! filter_exists egress "${EGRESS_HANDLE}"; then
      echo "[entrypoint] TC filters removed."
      return
    fi

    echo "[entrypoint] TC filters still present after cleanup attempt ${attempt}; retrying..."
    sleep 1
  done

  if filter_exists ingress "${HANDLE}"; then
    echo "[entrypoint] WARNING: ingress TC filter still present after cleanup (prio=${PRIO}, handle=${HANDLE})" >&2
  fi
  if filter_exists egress "${EGRESS_HANDLE}"; then
    echo "[entrypoint] WARNING: egress TC filter still present after cleanup (prio=${PRIO}, handle=${EGRESS_HANDLE})" >&2
  fi
}

cleanup() {
  if [ "${CLEANED_UP}" = "1" ]; then
    return
  fi
  CLEANED_UP=1
  set +e

  echo "[entrypoint] Cleaning up probe on ${IFACE} (prio=${PRIO}, handle=${HANDLE})"

  stop_process "${BPF_PID}" "gtp_latency_user"
  delete_owned_filters

  stop_process "${EXPORTER_PID}" "exporter"

  rm -f /tmp/gtp_latency.sock 2>/dev/null || true
  echo "[entrypoint] Cleanup complete."
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

python3 /app/exporter.py --port "${EXPORTER_PORT}" --metrics-path "${EXPORTER_PATH}" &
EXPORTER_PID=$!

sleep 1

if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
  wait "${EXPORTER_PID}" 2>/dev/null || true
  echo "[entrypoint] ERROR: exporter exited before BPF probe started" >&2
  exit 1
fi

DEBUG_ARGS=()
if [ "${MATCH_DEBUG}" = "1" ]; then
  DEBUG_ARGS+=(--debug-match)
fi

PACKET_ARGS=()
if [ "${PACKET_PAIRING}" = "1" ]; then
  PACKET_ARGS+=(--packet-pairing)
fi

TEID_ARGS=()
if [ -n "${TEIDS}" ]; then
  read -r -a TEID_ARGS <<< "${TEIDS}"
fi

/app/gtp_latency_user "${IFACE}" \
  --prio "${PRIO}" \
  --handle "${HANDLE}" \
  --mode "${LATENCY_MODE}" \
  --role "${PROBE_ROLE}" \
  "${DEBUG_ARGS[@]}" \
  "${PACKET_ARGS[@]}" \
  "${TEID_ARGS[@]}" &
BPF_PID=$!

while true; do
  if ! kill -0 "${BPF_PID}" 2>/dev/null; then
    wait "${BPF_PID}"
    exit $?
  fi

  if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    wait "${EXPORTER_PID}"
    exit $?
  fi

  sleep 1
done
