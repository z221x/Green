#!/bin/sh
# Rebuild the vendored gum stack into vendor/prefix and produce
# vendor/frida-gum/build-android-arm64/gum/libfrida-gum-1.0.a
# Run from kpms/green/vendor after frida-gum/ has been transferred and the
# meson14 venv created (see README.md).
set -e

VENDOR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GUM=$VENDOR/frida-gum
PREFIX=$VENDOR/prefix
MESON=$VENDOR/meson14/bin/meson
CROSS=$GUM/cross/android-arm64.ini

echo "== libffi =="
(cd $GUM/subprojects/libffi && \
    $MESON setup build-android --prefix=$PREFIX --cross-file $CROSS \
        -Ddefault_library=static >/dev/null && \
    ninja -C build-android >/dev/null && \
    mkdir -p $PREFIX/lib $PREFIX/include && \
    cp build-android/src/libffi.a $PREFIX/lib/ && \
    cp build-android/include/ffi.h $PREFIX/include/ && \
    cp src/aarch64/ffitarget.h $PREFIX/include/)
mkdir -p $PREFIX/lib/pkgconfig
cat > $PREFIX/lib/pkgconfig/libffi.pc <<PC
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libffi
Description: Library supporting Foreign Function Interfaces
Version: 3.4.6
Libs: -L\${libdir} -lffi
Cflags: -I\${includedir}
PC

echo "== capstone =="
(cd $GUM/subprojects/capstone && \
    $MESON setup build-android --prefix=$PREFIX --cross-file $CROSS \
        -Ddefault_library=static >/dev/null && \
    ninja -C build-android >/dev/null && \
    $MESON install -C build-android >/dev/null)

echo "== glib (force pcre2 fallback) =="
(cd $GUM/subprojects/glib && \
    PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig \
    $MESON setup build-android --prefix=$PREFIX --cross-file $CROSS \
        -Ddefault_library=static -Dtests=false \
        --force-fallback-for=pcre2 >/dev/null && \
    ninja -C build-android >/dev/null && \
    $MESON install -C build-android >/dev/null)

echo "== gum =="
(cd $GUM && \
    PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig \
    $MESON setup build-android-arm64 --cross-file $CROSS \
        -Dfrida_version=17.7.0 -Dgumjs=disabled -Dtests=disabled \
        -Dgumpp=disabled -Dinspector=disabled -Dgraft_tool=disabled >/dev/null && \
    ninja -C build-android-arm64 gum/libfrida-gum-1.0.a \
        subprojects/libdwarf/src/lib/libdwarf/libdwarf.a \
        subprojects/libunwind/src/libunwind.a >/dev/null)

echo "vendor build complete: $GUM/build-android-arm64/gum/libfrida-gum-1.0.a"

echo "== quickjs (native, for quickcompile) =="
(cd $GUM/subprojects/quickjs 2>/dev/null || { git clone -q --depth=1 https://github.com/frida/quickjs.git $GUM/subprojects/quickjs; cd $GUM/subprojects/quickjs; } && \
    $MESON setup build-native -Ddefault_library=static >/dev/null && \
    ninja -C build-native >/dev/null)

echo "== gumjs (arm64 payload library) =="
(cd $GUM && \
    PKG_CONFIG_PATH=$VENDOR/native-pc:/opt/homebrew/lib/pkgconfig \
    $MESON setup build-gumjs --cross-file cross/android-arm64.ini \
        --native-file $VENDOR/cross/native-file.ini \
        -Dfrida_version=17.7.0 -Dgumjs=enabled -Dquickjs=enabled \
        -Dtests=disabled -Dgumpp=disabled -Dinspector=disabled \
        -Dgraft_tool=disabled >/dev/null && \
    ninja -C build-gumjs gum/libfrida-gum-1.0.a \
        bindings/gumjs/libfrida-gumjs-1.0.a \
        subprojects/libdwarf/src/lib/libdwarf/libdwarf.a \
        subprojects/libunwind/src/libunwind.a >/dev/null)

echo "vendor build complete (incl. gumjs)"
