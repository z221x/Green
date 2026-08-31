# Green agent

`green_agent` has two parts:

- `libgreen_agent.so`: an in-process payload. It starts a per-pid abstract
  Unix socket and dispatches registered tools. The first registered tool is
  `green_hook`, which uses the real GumArm64Writer and the Green shadow
  backend.
- `green_agent_ctl`: root-side controller. It enables the target mm in the
  Green KPM, injects the payload with an AArch64 `ptrace` remote `dlopen`, and
  sends protocol requests to the payload.

The socket name is `@green.agent.<pid>`. Mutating tool requests require a root
peer (`SO_PEERCRED`); `PING` is available for liveness checks.

## Build

```sh
make -C kpms/green agent
```

Artifacts:

```text
kpms/green/build/libgreen_agent.so
kpms/green/build/green_agent_ctl
```

## Inject

The payload must be accessible by the target app. For an Android app, copy it
into the app's own data directory with the app UID and executable/readable
permissions. Then:

```sh
green_agent_ctl inject --pid PID \
  --so /data/user/0/<package>/cache/libgreen_agent.so
green_agent_ctl ping --pid PID
green_agent_ctl status --pid PID
green_agent_ctl self-test --pid PID
```

`inject` first calls `PR_GREEN_SHADOW_AGENT_ENABLE` from the root controller.
The injected app process can then call the normal Green shadow ABI with `pid=0`;
the KPM authorizes only that previously enabled mm. This avoids making the
shadow ABI globally available to unprivileged apps.

## Green hook request

```sh
green_agent_ctl hook --pid PID --target 0xTARGET \
  --replacement 0xREPLACEMENT --len 16
green_agent_ctl release --pid PID --target 0xTARGET
```

`self-test` exercises the real GumArm64Writer and Green shadow backend inside
the injected target. The explicit `hook` command accepts absolute in-process
addresses for a target function and replacement function. A future tool can
register a new tool id and handler without changing the transport or injector.
