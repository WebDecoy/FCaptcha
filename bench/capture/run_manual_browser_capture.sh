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
client_version=${FCAPTCHA_EXPECTED_CLIENT_VERSION:-1.51.4}
recorder_log=/scratch/logs/manual-${FCAPTCHA_CAPTURE_MODE}.log
accessibility_workflow=${FCAPTCHA_ACCESSIBILITY_WORKFLOW:-}
form_fixture=${FCAPTCHA_FORM_FIXTURE:-basic}
capture_port=${FCAPTCHA_CAPTURE_PORT:-0}

mkdir -p /scratch/results /scratch/logs

/usr/local/bin/fcaptcha-tcp-relay 127.0.0.1 18881 "$upstream_host" "$upstream_port" \
  >/scratch/logs/fcaptcha-relay.log 2>&1 &
relay_pid=$!

cleanup() {
  status=$?
  trap - EXIT INT TERM
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

if [ -n "$accessibility_workflow" ]; then
  : "${FCAPTCHA_INPUT_TOOL_NAME:?Accessibility capture requires the input tool name}"
  : "${FCAPTCHA_INPUT_TOOL_VERSION:?Accessibility capture requires the input tool version}"
  : "${FCAPTCHA_INPUT_TOOL_SETTINGS:?Accessibility capture requires the relevant tool settings}"
  python3 "$source_root/bench/capture/camoufox_bench.py" \
    --accessibility-manual --modes "$FCAPTCHA_CAPTURE_MODE" --observations --timeout 300 \
    --environment-label "$FCAPTCHA_CAPTURE_ENVIRONMENT" \
    --manual-workflow "$accessibility_workflow" \
    --input-tool-name "$FCAPTCHA_INPUT_TOOL_NAME" \
    --input-tool-version "$FCAPTCHA_INPUT_TOOL_VERSION" \
    --input-tool-settings "$FCAPTCHA_INPUT_TOOL_SETTINGS" \
    --form-fixture "$form_fixture" \
    --capture-port "$capture_port" \
    --consent-confirmed --isolated-test-context \
    --expected-client-version "$client_version" \
    --server "$server_url" \
    --out "$FCAPTCHA_CAPTURE_OUT" \
    >"$recorder_log" 2>&1 &
else
  python3 "$source_root/bench/capture/camoufox_bench.py" \
    --manual --modes "$FCAPTCHA_CAPTURE_MODE" --observations --timeout 300 \
    --capture-port "$capture_port" \
    --environment-label "$FCAPTCHA_CAPTURE_ENVIRONMENT" \
    --expected-client-version "$client_version" \
    --server "$server_url" \
    --out "$FCAPTCHA_CAPTURE_OUT" \
    >"$recorder_log" 2>&1 &
fi
recorder_pid=$!

attempt=0
while [ "$attempt" -lt 120 ]; do
  if grep -q 'Open http://127.0.0.1:' "$recorder_log"; then
    break
  fi
  if ! kill -0 "$recorder_pid" 2>/dev/null; then
    cat "$recorder_log" >&2
    wait "$recorder_pid"
    exit $?
  fi
  attempt=$((attempt + 1))
  sleep 0.25
done
if [ "$attempt" -ge 120 ]; then
  echo "recorder did not publish a capture URL" >&2
  cat "$recorder_log" >&2
  exit 1
fi

cat "$recorder_log"
wait "$recorder_pid"
kill "$relay_pid" 2>/dev/null || true
trap - EXIT INT TERM
cat "$recorder_log"

touch /scratch/capture-ready
sleep "${FCAPTCHA_CAPTURE_HOLD_SECONDS:-300}"
