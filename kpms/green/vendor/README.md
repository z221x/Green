# Vendored dependencies (not committed)

The directories below are fetched/built locally and are **git-ignored**:

| Path | Source | Purpose |
|---|---|---|
| `frida-gum/` | frida-gum + subprojects (glib, capstone, libffi, libdwarf, libunwind) | the real GumInterceptor stack |
| `prefix/` | cross-built arm64 static libs (glib/capstone/libffi + headers + .pc) | link inputs for the payload |
| `meson14/` | local Python venv with meson 1.4.2 (frida-era) + ninja + setuptools | build tool |
| `scratch/` | throwaway test sources/binaries | — |

Only `cross/`, `setup.sh` and this README are committed.

## Rebuild from scratch

```sh
# 1. sources: copy the reference checkout into vendor/
rsync -a --exclude='.git' --exclude='build-android-arm64' \
    ../tmp/frida-gum/ frida-gum/

# 2. tool venv
python3 -m venv meson14
meson14/bin/pip install meson==1.4.2 ninja setuptools

# 3. libffi / glib / capstone -> prefix  (see log excerpts in setup.sh)
./setup.sh
```

`setup.sh` performs the full flow: standalone cross builds of libffi, glib
(force-fallback pcre2) and capstone into `prefix/`, then the gum build
against `prefix` via `PKG_CONFIG_PATH`, producing
`frida-gum/build-android-arm64/gum/libfrida-gum-1.0.a`.
