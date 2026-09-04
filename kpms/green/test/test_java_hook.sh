#!/bin/sh
# Build/deploy and run the Java hook probe against a rooted Android device.
# Usage:
#   ./test_java_hook.sh [package]
#   PROBE_SCRIPT=/path/to/probe.js ./test_java_hook.sh [package]
# Environment:
#   ADB=/path/to/adb, REBUILD=1, PID=<existing pid>, PORT=27042,
#   PROBE_SCRIPT=/path/to/probe.js, LAUNCH_WAIT=5, CAPTURE_LOGS=1,
#   LOG_PREFIX=/tmp/green-java-hook

set -eu

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GREEN_DIR=$(CDPATH= cd -- "$SELF_DIR/.." && pwd)
CLI="$GREEN_DIR/cli/green.py"
ADB=${ADB:-adb}
PACKAGE=${1:-com.miui.calculator}
PORT=${PORT:-27042}
REMOTE_DIR=${REMOTE_DIR:-/data/local/tmp}
PROBE_SCRIPT=${PROBE_SCRIPT:-$SELF_DIR/java_hook_probe.js}
LAUNCH_WAIT=${LAUNCH_WAIT:-5}
CAPTURE_LOGS=${CAPTURE_LOGS:-1}
LOG_PREFIX=${LOG_PREFIX:-/tmp/green-java-hook-$$}

collect_logs() {
    [ "$CAPTURE_LOGS" = "1" ] || return 0
    "$ADB" logcat -b crash -d -v threadtime -t 300 \
        >"${LOG_PREFIX}.crash.log" 2>/dev/null || true
    "$ADB" logcat -d -v threadtime -t 300 \
        >"${LOG_PREFIX}.logcat.log" 2>/dev/null || true
    echo "[*] crash log: ${LOG_PREFIX}.crash.log" >&2
    echo "[*] logcat tail: ${LOG_PREFIX}.logcat.log" >&2
}

trap collect_logs EXIT

if [ ! -f "$PROBE_SCRIPT" ]; then
    echo "missing probe script: $PROBE_SCRIPT" >&2
    exit 1
fi

if [ "${REBUILD:-0}" = "1" ]; then
    : "${ANDROID_NDK:?Set ANDROID_NDK when REBUILD=1}"
    make -C "$GREEN_DIR" agent client
fi

PAYLOAD="$GREEN_DIR/build/libgreen_agent.so"
SERVER="$GREEN_DIR/build/green"

if [ ! -f "$PAYLOAD" ]; then
    echo "missing $PAYLOAD (run: ANDROID_NDK=... make -C $GREEN_DIR agent)" >&2
    exit 1
fi

echo "[*] pushing payload"
"$ADB" push "$PAYLOAD" "$REMOTE_DIR/libgreen_agent.so"
if [ -f "$SERVER" ]; then
    "$ADB" push "$SERVER" "$REMOTE_DIR/green"
    "$ADB" shell su -c "chmod 755 $REMOTE_DIR/green $REMOTE_DIR/libgreen_agent.so"
fi

SERVER_PID=$("$ADB" shell pidof green 2>/dev/null | tr -d '\r' || true)
if [ -z "$SERVER_PID" ]; then
    if [ ! -f "$SERVER" ]; then
        echo "green server is not running and $SERVER is unavailable; build client or start it manually" >&2
        exit 1
    fi
    echo "[*] starting green server"
    # The device binary is already the server; it has no `server` subcommand.
    "$ADB" shell su -c "nohup $REMOTE_DIR/green >/data/local/tmp/green.log 2>&1 &"
    sleep 1
    SERVER_PID=$("$ADB" shell pidof green 2>/dev/null | tr -d '\r' || true)
    if [ -z "$SERVER_PID" ]; then
        echo "green server failed to start; inspect $REMOTE_DIR/green.log" >&2
        exit 1
    fi
fi

if ! "$ADB" forward --list 2>/dev/null | awk -v p="tcp:$PORT" '$2 == p { found=1 } END { exit(found ? 0 : 1) }'; then
    "$ADB" forward "tcp:$PORT" "tcp:$PORT"
fi

if [ -n "${PID:-}" ]; then
    TARGET_PID=$PID
else
    echo "[*] launching $PACKAGE"
    if [ "${KEEP_RUNNING:-0}" != "1" ]; then
        # A payload is loaded once per process; stop this package so the
        # freshly pushed .so is guaranteed to be mapped on the next start.
        "$ADB" shell am force-stop "$PACKAGE"
    fi
    "$ADB" shell monkey -p "$PACKAGE" 1 >/dev/null
    sleep "$LAUNCH_WAIT"
    TARGET_PID=$("$ADB" shell pidof "$PACKAGE" 2>/dev/null | awk '{print $1}' | tr -d '\r')
fi

if [ -z "$TARGET_PID" ]; then
    echo "could not find a PID for $PACKAGE" >&2
    exit 1
fi

echo "[*] attaching to $PACKAGE (pid $TARGET_PID)"
echo "[*] Ctrl-C detaches; target crash/abort output is in logcat"
python3 "$CLI" attach -p "$TARGET_PID" -l "$PROBE_SCRIPT"
