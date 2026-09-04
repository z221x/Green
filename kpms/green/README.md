# Green

Green is an Android ARM64 hook runtime built around KernelPatch Module (KPM)
shadow pages and the stock Frida GumJS runtime.

## Architecture

```
host cli/green.py ── TCP ──> root green server
                              ├─ ptrace injects green_hook/agent payload
                              ├─ generates + registers per-process token in KPM
                              └─ sends token over the root-only control socket
                                      │
                                      ▼
                              target: stock GumJS + frida-java-bridge
                              every target write -> authenticated shadow prctl
```

There is no broker and no custom JavaScript prelude/trampoline. KPM receives
the token on every request; an agent cannot use shadow before the server has
provisioned it.

## Layout

```
kpms/green/
├── green_hook/
│   ├── agent/                 # injected payload only
│   │   ├── green_agent_standard.c
│   │   ├── green_shadow_client.c
│   │   ├── gummemory-green-payload.c
│   │   └── frida-java-bridge/ # reviewed bridge bundle
│   └── frida-core/            # host compatibility boundary/documentation
├── shadow/                    # KPM shadow implementation
├── emu/                       # ARM64 same-page fault emulator
├── common/                    # injector and root-side token provisioning
├── server/                    # on-device root daemon
├── cli/                       # host Python CLI
├── test/                      # device/API smoke tests and hook scripts
├── build/                     # generated artifacts (ignored)
└── vendor/                    # vendored Frida Gum/QuickJS inputs
```

## Build

```sh
cd kpms/green
make TARGET_COMPILE=aarch64-elf- KP_DIR=../../kernel green.kpm
ANDROID_NDK=/path/to/ndk make client agent testhook
```

`green_hook/agent/link-payload.sh` links `libgreen_agent.so` from stock
`libfrida-gumjs-1.0.a` and the patched bridge bundle. It does not compile any
legacy Green agent, prelude, broker, or handwritten relocator.

## Deploy

```sh
adb push build/green.kpm /data/local/tmp/green.kpm
# Load the KPM with the KernelPatch loader used by your device.
adb push build/green /data/local/tmp/green
adb push build/libgreen_agent.so /data/local/tmp/libgreen_agent.so
adb shell su -c 'chmod 755 /data/local/tmp/green /data/local/tmp/libgreen_agent.so'
adb shell su -c '/data/local/tmp/green'
adb forward tcp:27042 tcp:27042
python3 cli/green.py ps
```

If token registration fails, the daemon reports that `green.kpm` must be
loaded; no fallback memory-write path is attempted.

## Frida-compatible script example

```js
console.log('pid:', Process.id, 'arch:', Process.arch);
const open = Module.getExportByName('libc.so', 'open');
Interceptor.attach(open, {
  onEnter(args) { console.log('open:', args[0].readCString()); },
  onLeave(retval) { console.log('open ->', retval.toInt32()); }
});
```

Run it with:

```sh
python3 cli/green.py attach -f com.example.app -l test/example_hook.js
```

## Authenticated shadow ABI

```c
prctl(PR_GREEN_SHADOW_TOKEN_REGISTER, pid, token, 0, 0); /* root only */
prctl(PR_GREEN_SHADOW_REQUEST, token, &rpc, 0, 0);       /* every operation */
prctl(PR_GREEN_SHADOW_TOKEN_REVOKE, pid, token, 0, 0);  /* root only */
```

`rpc.op` is `PATCH`, `RELEASE`, or `COUNT`; patch requests are capped at one
4-KB page. Contiguous page-table hints are split before a single leaf is
replaced, and non-executable data pages retain their original permissions.

## Scope

The runtime exposes the standard GumJS NativePointer, Memory, Module,
Interceptor, NativeFunction/Callback, Process, Thread, Script, and Java APIs.
Stalker and platform-specific non-Android backends remain outside this ARM64
KPM target. See `doc/KNOWN-ISSUES.md` for kernel-version caveats.
