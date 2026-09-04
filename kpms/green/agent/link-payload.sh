#!/bin/bash
# Links the payload (script host) against frida-gum + gumjs + glib/ffi statics.
# All paths are relative to the repo root (kpms/green).
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD_DIR="$ROOT/build"
mkdir -p "$BUILD_DIR"

NDK="${ANDROID_NDK:-$(ls -d "$HOME/Library/Android/sdk/ndk/"* 2>/dev/null | sort -V | tail -1)}"
CC="$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android35-clang"
CC=$(echo $CC)  # glob expand

TP=$ROOT/tmp/prefix/lib
FGJ=$ROOT/vendor/frida-gum/build-gumjs/bindings/gumjs
FG=$ROOT/vendor/frida-gum/build-gumjs/gum
CS=$ROOT/vendor/frida-gum/subprojects/capstone/include/capstone

# Generate prelude.inc from prelude.js (single source of truth)
python3 - <<'PYGEN'
src = open('agent/prelude.js').read()
out = ['/* Auto-generated from prelude.js - do not edit. */',
       'static const char kGreenPrelude[] =']
for line in src.split('\n'):
    esc = line.replace('\\','\\\\').replace('"','\\"')
    out.append('    "' + esc + '\\n"')
out[-1] += ';'
open('build/prelude.inc','w').write('\n'.join(out) + '\n')
PYGEN

# Generate fjb.inc from the patched frida-java-bridge IIFE
python3 - <<'PYGEN2'
src = open('agent/frida-java-bridge/fjb.iife.js').read()
out = ['/* Auto-generated from agent/frida-java-bridge/fjb.iife.js (frida-java-bridge) - do not edit. */',
       'static const char kFjbBundle[] =']
for line in src.split('\n'):
    esc = line.replace('\\','\\\\').replace('"','\\"')
    out.append('    "' + esc + '\\n"')
out[-1] += ';'
open('build/fjb.inc','w').write('\n'.join(out) + '\n')
PYGEN2

# Compile the profiler stub
$CC -c -O2 -w -o build/gumprofiler-stub.o agent/gumprofiler-stub.c \
  -Iagent/stub-include \
  -I$ROOT/tmp/prefix/include/glib-2.0 -I$ROOT/tmp/prefix/lib/glib-2.0/include \
  -Ivendor/frida-gum/libs/gum/prof -Ivendor/frida-gum/gum

# Link the payload
$CC -D_GNU_SOURCE -fPIC -shared -O2 -Wall -Wextra -pthread \
  -Iinclude \
  -Ivendor/frida-gum -Ivendor/frida-gum/bindings -Ivendor/frida-gum/build-gumjs -Ivendor/frida-gum/gum \
  -Ivendor/frida-gum/subprojects/capstone/include/capstone \
  -Ibuild \
  -I$ROOT/tmp/prefix/include/glib-2.0 -I$ROOT/tmp/prefix/lib/glib-2.0/include \
  -Ivendor/prefix/include/quickjs \
  -o build/libgreen_agent.so \
  agent/green_agent.c agent/gummemory-green-payload.c agent/gumwriter.c agent/insn.c agent/relocator.c agent/frida-java-bridge/java_bridge.c \
  -Wl,--allow-multiple-definition \
  -Wl,--start-group \
  build/gumprofiler-stub.o \
  vendor/prefix/lib/libquickjs.a \
  $FGJ/libfrida-gumjs-1.0.a \
  $FG/libfrida-gum-1.0.a \
  $TP/libgobject-2.0.a $TP/libglib-2.0.a $TP/libgthread-2.0.a \
  $TP/libgio-2.0.a $TP/libgmodule-2.0.a $TP/libffi.a \
  $TP/libpcre2-8.a $TP/libpcre2-16.a $TP/libpcre2-32.a \
  $TP/libcapstone.a \
  vendor/frida-gum/build-gumjs/subprojects/json-glib/json-glib/libjson-glib-1.0.a \
  vendor/frida-gum/build-gumjs/subprojects/tinycc/libtcc.a \
  vendor/frida-gum/build-gumjs/subprojects/libunwind/src/libunwind.a \
  vendor/frida-gum/build-gumjs/subprojects/libdwarf/src/lib/libdwarf/libdwarf.a \
  -Wl,--end-group \
  -lm -llog -ldl -lc++abi -lc

echo "payload linked: build/libgreen_agent.so"
