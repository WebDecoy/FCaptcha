#!/bin/sh
set -eu

display_name=${DISPLAY:-:99}
scratch_root=/scratch
runtime_root=$scratch_root/runtime
cache_root=$scratch_root/cache
config_root=$scratch_root/config
data_root=$scratch_root/data

mkdir -p \
  "$runtime_root" \
  "$cache_root" \
  "$config_root" \
  "$data_root" \
  "$scratch_root/chrome" \
  "$scratch_root/logs" \
  /tmp/.X11-unix
chmod 700 "$runtime_root"
chmod 1777 /tmp/.X11-unix

cleanup() {
  for child_pid in "${websockify_pid:-}" "${vnc_pid:-}" "${chrome_pid:-}" "${xvfb_pid:-}"; do
    if [ -n "$child_pid" ]; then kill "$child_pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT INT TERM

DISPLAY=$display_name Xvfb "$display_name" -screen 0 1280x900x24 -nolisten tcp -noreset \
  >"$scratch_root/logs/xvfb.log" 2>&1 &
xvfb_pid=$!

attempt=0
while [ ! -S /tmp/.X11-unix/X99 ] && [ "$attempt" -lt 100 ]; do
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ ! -S /tmp/.X11-unix/X99 ]; then
  echo "Xvfb did not create its display socket" >&2
  exit 1
fi

set -- \
  --no-sandbox \
  --disable-gpu \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9223 \
  --user-data-dir="$scratch_root/chrome" \
  --window-size=1280,900 \
  --no-first-run \
  --no-default-browser-check \
  --disable-sync \
  --disable-background-networking \
  --disable-component-update \
  --disable-domain-reliability \
  --disable-client-side-phishing-detection \
  --disable-default-apps \
  --disable-extensions \
  --disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication \
  --metrics-recording-only \
  --disable-breakpad \
  --disable-crash-reporter \
  --disable-search-engine-choice-screen \
  --disable-translate \
  --no-service-autorun \
  --password-store=basic
if [ "${FCAPTCHA_REDUCED_MOTION:-0}" = 1 ]; then
  set -- "$@" --force-prefers-reduced-motion
fi

DISPLAY=$display_name \
XDG_CACHE_HOME=$cache_root \
XDG_CONFIG_HOME=$config_root \
XDG_DATA_HOME=$data_root \
XDG_RUNTIME_DIR=$runtime_root \
/usr/bin/chromium "$@" about:blank >"$scratch_root/logs/chromium.log" 2>&1 &
chrome_pid=$!

DISPLAY=$display_name x11vnc -display "$display_name" -localhost -forever -shared -nopw -rfbport 5900 \
  >"$scratch_root/logs/x11vnc.log" 2>&1 &
vnc_pid=$!

websockify --web=/usr/share/novnc 0.0.0.0:6080 127.0.0.1:5900 \
  >"$scratch_root/logs/websockify.log" 2>&1 &
websockify_pid=$!

attempt=0
while [ "$attempt" -lt 150 ]; do
  if /app/.venv/bin/python -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:9223/json/version", timeout=0.2).read()' \
    >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.1
done
if [ "$attempt" -ge 150 ]; then
  echo "Chromium did not become ready" >&2
  exit 1
fi

if [ "${FCAPTCHA_PROFILE_SETUP:-0}" = 1 ]; then
  touch "$scratch_root/profile-setup-ready"
  setup_attempt=0
  setup_limit=${FCAPTCHA_PROFILE_SETUP_SECONDS:-300}
  while [ ! -f "$scratch_root/operator-ready" ] && [ "$setup_attempt" -lt "$setup_limit" ]; do
    setup_attempt=$((setup_attempt + 1))
    sleep 1
  done
  if [ ! -f "$scratch_root/operator-ready" ]; then
    echo "operator profile setup timed out" >&2
    exit 1
  fi
fi

/source/bench/capture/run_manual_browser_capture.sh
