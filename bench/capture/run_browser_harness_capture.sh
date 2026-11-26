#!/bin/sh
set -eu

: "${FCAPTCHA_SECRET:?Set the test-only FCaptcha verification secret}"
: "${FCAPTCHA_CAPTURE_MODE:?Set form, invisible, or widget}"
: "${FCAPTCHA_CAPTURE_OUT:?Set a fresh output directory under /scratch/results}"
: "${FCAPTCHA_CAPTURE_ENVIRONMENT:?Describe the exact browser, OS, architecture, machine, and profile}"

case "$FCAPTCHA_CAPTURE_MODE" in
  form|invisible|widget) ;;
  *) echo "unsupported FCAPTCHA_CAPTURE_MODE: $FCAPTCHA_CAPTURE_MODE" >&2; exit 2 ;;
esac
case "$FCAPTCHA_CAPTURE_OUT" in
  /scratch/results/*) ;;
  *) echo "FCAPTCHA_CAPTURE_OUT must be under /scratch/results" >&2; exit 2 ;;
esac

source_root=${FCAPTCHA_SOURCE_ROOT:-/source}
upstream_host=${FCAPTCHA_UPSTREAM_HOST:-wd-fcaptcha-proxy-0010}
upstream_port=${FCAPTCHA_UPSTREAM_PORT:-8080}
server_url=http://127.0.0.1:18881
client_version=${FCAPTCHA_EXPECTED_CLIENT_VERSION:-1.52.0}
driver_version=${BROWSER_HARNESS_VERSION:-0.1.13}
driver_commit=${BROWSER_HARNESS_COMMIT:-c24e5072ee66f8499bacd663f4f4bcb089bc4492}
recorder_log=/scratch/logs/recorder-${FCAPTCHA_CAPTURE_MODE}.log
harness_log=/scratch/logs/harness-${FCAPTCHA_CAPTURE_MODE}.log

mkdir -p /scratch/results /scratch/logs

/usr/local/bin/fcaptcha-tcp-relay 127.0.0.1 18881 "$upstream_host" "$upstream_port" \
  >/scratch/logs/fcaptcha-relay.log 2>&1 &
relay_pid=$!

attempt=0
while [ "$attempt" -lt 40 ]; do
  if python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18881/health", timeout=0.2).read()' \
      >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.25
done
if [ "$attempt" -ge 40 ]; then
  echo "loopback FCaptcha relay did not become ready" >&2
  cat /scratch/logs/fcaptcha-relay.log >&2
  exit 1
fi

(
  printf 'completed\n' | python3 "$source_root/bench/capture/camoufox_bench.py" \
    --external-driver --modes "$FCAPTCHA_CAPTURE_MODE" --observations --timeout 180 \
    --environment-label "$FCAPTCHA_CAPTURE_ENVIRONMENT" \
    --driver-name browser-harness \
    --driver-version "$driver_version" \
    --driver-commit "$driver_commit" \
    --expected-client-version "$client_version" \
    --server "$server_url" \
    --out "$FCAPTCHA_CAPTURE_OUT"
) >"$recorder_log" 2>&1 &
recorder_pid=$!

cleanup() {
  status=$?
  trap - EXIT INT TERM
  kill "$recorder_pid" 2>/dev/null || true
  kill "$relay_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    for log in /scratch/logs/*.log; do
      if [ -f "$log" ]; then
        echo "--- $log" >&2
        tail -n 160 "$log" >&2
      fi
    done
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

capture_url=
attempt=0
while [ "$attempt" -lt 120 ]; do
  if ! kill -0 "$recorder_pid" 2>/dev/null; then
    cat "$recorder_log" >&2
    recorder_status=0
    wait "$recorder_pid" || recorder_status=$?
    exit "$recorder_status"
  fi
  capture_url=$(sed -n 's/.*\(http:\/\/127\.0\.0\.1:[0-9][0-9]*\/\).*/\1/p' "$recorder_log" | head -n 1)
  [ -n "$capture_url" ] && break
  attempt=$((attempt + 1))
  sleep 0.25
done
if [ -z "$capture_url" ]; then
  echo "recorder did not publish a capture URL" >&2
  cat "$recorder_log" >&2
  exit 1
fi

env -i \
PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin \
DISPLAY="${DISPLAY:-:99}" \
TMPDIR=/tmp \
XDG_CACHE_HOME=/scratch/cache \
XDG_CONFIG_HOME=/scratch/config \
XDG_DATA_HOME=/scratch/data \
XDG_RUNTIME_DIR=/scratch/runtime \
BH_HOME=/scratch/browser-harness \
BH_TELEMETRY=0 \
BU_CDP_URL=http://127.0.0.1:9223 \
FCAPTCHA_CAPTURE_URL="$capture_url" \
FCAPTCHA_CAPTURE_MODE="$FCAPTCHA_CAPTURE_MODE" \
/usr/bin/timeout 120s /app/.venv/bin/browser-harness \
  <"$source_root/bench/capture/browser_harness_task.py" \
  >"$harness_log" 2>&1

wait "$recorder_pid"
kill "$relay_pid" 2>/dev/null || true
trap - EXIT INT TERM
cat "$harness_log"
cat "$recorder_log"

if [ "${FCAPTCHA_CAPTURE_HOLD:-0}" = 1 ]; then
  touch /scratch/capture-ready
  sleep "${FCAPTCHA_CAPTURE_HOLD_SECONDS:-120}"
fi
