#!/bin/sh
# Build the Green payload from the stock Frida GumJS runtime and the
# Green-specific authenticated shadow memory seam.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
BUILD_DIR="$ROOT/build"
mkdir -p "$BUILD_DIR"

NDK=${ANDROID_NDK:?ANDROID_NDK must point at an Android NDK}
HOST_TAG=${NDK_HOST_TAG:-darwin-x86_64}
CC="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android35-clang"
if [ ! -x "$CC" ]; then
  echo "missing Android compiler: $CC" >&2
  exit 1
fi

FGJ="$ROOT/vendor/frida-gum/build-gumjs/bindings/gumjs"
FG="$ROOT/vendor/frida-gum/build-gumjs/gum"
TP="$ROOT/vendor/prefix/lib"

python3 - "$ROOT/green_hook/agent/frida-java-bridge/fjb.iife.js" \
        "$BUILD_DIR/fjb.inc" <<'PY'
import sys
src, dst = sys.argv[1:]
lines = open(src, encoding='utf-8').read().splitlines()
with open(dst, 'w', encoding='utf-8') as f:
    f.write('/* Generated; edit frida-java-bridge/fjb.iife.js instead. */\n')
    f.write('static const char kFjbBundle[] =\n')
    for line in lines:
        escaped = line.replace('\\', '\\\\').replace('"', '\\"')
        f.write('    "' + escaped + '\\n"\n')
    f.write(';\n')
PY

COMMON_FLAGS="-D_GNU_SOURCE -fPIC -shared -O2 -Wall -Wextra -pthread"
INCLUDES="-I$ROOT/include -I$ROOT/green_hook/agent \
 -I$ROOT/vendor/frida-gum -I$ROOT/vendor/frida-gum/bindings \
 -I$ROOT/vendor/frida-gum/bindings/gumjs -I$ROOT/vendor/frida-gum/gum \
 -I$ROOT/vendor/frida-gum/build-gumjs \
 -I$ROOT/vendor/frida-gum/subprojects/capstone/include/capstone \
 -I$ROOT/vendor/frida-gum/subprojects/json-glib \
 -I$ROOT/vendor/frida-gum/build-gumjs/subprojects/json-glib/json-glib \
 -I$ROOT/vendor/frida-gum/build-gumjs/subprojects/json-glib \
 -I$ROOT/vendor/prefix/include/quickjs \
 -I$ROOT/vendor/prefix/include/glib-2.0 \
 -I$ROOT/vendor/prefix/lib/glib-2.0/include -I$BUILD_DIR"

# gummemory-green-payload.c overrides only Gum's memory backend.  All target
# writes go through green_agent_shadow_request(); the rest of GumJS remains
# unmodified and therefore exposes the standard Frida API surface.
$CC $COMMON_FLAGS $INCLUDES -o "$BUILD_DIR/libgreen_agent.so" \
  green_hook/agent/green_agent_standard.c \
  green_hook/agent/green_shadow_client.c \
  green_hook/agent/gummemory-green-payload.c \
  -Wl,--allow-multiple-definition -Wl,--start-group \
  vendor/prefix/lib/libquickjs.a \
  "$FGJ/libfrida-gumjs-1.0.a" "$FG/libfrida-gum-1.0.a" \
  "$TP/libgobject-2.0.a" "$TP/libglib-2.0.a" "$TP/libgthread-2.0.a" \
  "$TP/libgio-2.0.a" "$TP/libgmodule-2.0.a" "$TP/libffi.a" \
  "$TP/libpcre2-8.a" "$TP/libpcre2-16.a" "$TP/libpcre2-32.a" \
  "$TP/libcapstone.a" \
  vendor/frida-gum/build-gumjs/subprojects/json-glib/json-glib/libjson-glib-1.0.a \
  vendor/frida-gum/build-gumjs/subprojects/tinycc/libtcc.a \
  vendor/frida-gum/build-gumjs/subprojects/libunwind/src/libunwind.a \
  vendor/frida-gum/build-gumjs/subprojects/libdwarf/src/lib/libdwarf/libdwarf.a \
  -Wl,--end-group -lm -llog -ldl -lc++abi -lc

echo "payload linked: $BUILD_DIR/libgreen_agent.so"
