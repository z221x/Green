# Green agent

`green_agent` has two parts:

- `libgreen_agent.so`: an in-process payload. It starts a per-pid abstract
  Unix socket and dispatches registered tools. The first registered tool is
  `green_hook`, which uses the real GumArm64Writer and the Green shadow
  backend.
- The `green agent` subcommand (in `kpms/green/cli`): root-side injector,
  broker and protocol client.  There is a single CLI binary.

## Privilege model

The agent has **no kernel privileges, never calls the Green prctl ABI, and
links none of the gum sources**.  A hook request carries only the target and
replacement addresses; the privileged work happens in a root-side broker:

```text
agent (target process, unprivileged, pure transport)
   |  1. socket request: {target addr, replacement addr}
   v
green cli  `shadow broker`  (root)
   |  2. process_vm_readv(target): snapshot the original page
   |  3. GumArm64Writer emits the redirect into the snapshot
   |  4. prctl(PR_GREEN_SHADOW_PATCH/RELEASE/COUNT)
   v
KPM (page-table operations)
```

- `green shadow broker -p <pid>` listens on `@green.broker.<pid>`, serves only
  peers whose uid equals the target process's uid, snapshots pages
  cross-process with `process_vm_readv`, and commits through the shadow ABI,
  so one broker instance is bound to exactly one target.
- The agent's own socket is `@green.agent.<pid>`; `PING` works without a
  broker.

## Build

```sh
make -C kpms/green agent
```

Artifacts:

```text
kpms/green/build/libgreen_agent.so
kpms/green/build/green_agent_ctl
```

## Inject and use

The payload must be readable/executable by the target app; copy it into the
app's own data directory with the app uid. Then, as root:

```sh
# 1. inject
green_agent_ctl inject --pid PID \
  --so /data/user/0/<package>/cache/libgreen_agent.so

# 2. start the root broker for this target
green shadow broker -p PID

# 3. liveness + green_hook self-test (real GumArm64Writer + shadow backend)
green_agent_ctl ping --pid PID
green_agent_ctl self-test --pid PID

# 4. explicit hook by absolute in-process addresses
green_agent_ctl hook --pid PID --target 0xTARGET \
  --replacement 0xREPLACEMENT --len 16
green_agent_ctl release --pid PID --target 0xTARGET
```

The tool registry (`green_agent_register_tool`) lets future Green tools add
new tool ids and handlers without changing the transport or the injector.
