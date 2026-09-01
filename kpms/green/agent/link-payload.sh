#!/bin/bash
# Links the payload (script host) against frida-gum + gumjs + glib/ffi statics.
set -e
NDK=$HOME/Library/Android/sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/darwin-x86_64/bin
CC="$NDK/aarch64-linux-android35-clang"
ROOT=/Users/work/Desktop/work/work/KernelPatch/kpms/green
TP=$ROOT/tmp/prefix/lib
FGJ=$ROOT/vendor/frida-gum/build-gumjs/bindings/gumjs
FG=$ROOT/vendor/frida-gum/build-gumjs/gum
CS=$ROOT/vendor/frida-gum/subprojects/capstone/include/capstone

cd "$ROOT"
$CC -c -O2 -w -o agent/gumprofiler-stub.o agent/gumprofiler-stub.c \
  -I$ROOT/tmp/prefix/include/glib-2.0 -I$ROOT/tmp/prefix/lib/glib-2.0/include \
  -Iagent/stub-include
$CC -D_GNU_SOURCE -fPIC -shared -O2 -Wall -Wextra -pthread \
  -Iinclude -Ivendor/frida-gum -Ivendor/frida-gum/bindings -Ivendor/frida-gum/build-gumjs -Ivendor/frida-gum/gum \
  -Ivendor/frida-gum/subprojects/capstone/include/capstone \
  -I$ROOT/tmp/prefix/include/glib-2.0 -I$ROOT/tmp/prefix/lib/glib-2.0/include \
  -Ivendor/prefix/include/quickjs -Igreen_hook/vendor/gum \
  -o build/libgreen_agent.so agent/green_agent.c \
  agent/gummemory-green-payload.c \
  -Wl,--allow-multiple-definition \
  -Wl,--start-group \
  $FGJ/libfrida-gumjs-1.0.a \
  $FG/libfrida-gum-1.0.a \
  $TP/libgobject-2.0.a $TP/libglib-2.0.a $TP/libgthread-2.0.a \
  $TP/libgio-2.0.a $TP/libgmodule-2.0.a $TP/libffi.a \
  $TP/libpcre2-8.a $TP/libpcre2-16.a $TP/libpcre2-32.a \
  $TP/libcapstone.a \
  vendor/frida-gum/build-gumjs/subprojects/json-glib/json-glib/libjson-glib-1.0.a \
  vendor/frida-gum/build-gumjs/subprojects/tinycc/libtcc.a \
  agent/gumprofiler-stub.o \
  vendor/frida-gum/build-gumjs/subprojects/libunwind/src/libunwind.a \
  vendor/frida-gum/build-gumjs/subprojects/libdwarf/src/lib/libdwarf/libdwarf.a \
  $ROOT/vendor/prefix/lib/libquickjs.a \
  -Wl,--end-group \
  -lm -llog -ldl -lc++abi -lc
echo "payload linked: build/libgreen_agent.so"
