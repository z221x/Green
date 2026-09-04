# Vendored dependencies (not committed)

git-ignored directories (fetched/built locally):

- `frida-gum/` — frida-gum source + subprojects (glib, capstone, libffi,
  libdwarf, libunwind, quickjs)
- `prefix/` — cross-built arm64 static libs + headers + .pc files
- `meson14/` — Python venv with meson 1.4.2 (frida-era), ninja, setuptools
- `scratch/` — throwaway test sources

Committed: `cross/` (meson machine files + arm64 pkg-config wrapper),
`native-pkg-config`, `setup.sh`, this README.

## What the build produces

- `prefix/` — arm64 static: glib/gobject/gio, capstone 5, libffi, lzma, zstd,
  quickjs (frida fork)
- `frida-gum/build-gumjs/gum/libfrida-gum-1.0.a` — gum core incl.
  GumInterceptor (trampoline + relocation); Green overrides only the memory
  seam in `green_hook/agent/gummemory-green-payload.c`
- `frida-gum/build-gumjs/bindings/gumjs/libfrida-gumjs-1.0.a` — QuickJS
  script backend + the frida JS API runtime (Interceptor, Memory, Module...)

## Rebuild

```sh
./setup.sh
```

Requires: Android NDK (ANDROID_NDK env or default location), meson 1.4.2
venv at `meson14/` (recreate with `python3 -m venv` + pip install),
network for the first clone.
