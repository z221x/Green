# Green Frida agent

This directory is the only injected user-space payload. It embeds the
vendored Frida GumJS runtime and the patched `frida-java-bridge` bundle.

- `green_agent_standard.c` is the GumScript/QJS host and control socket.
- `green_shadow_client.c` issues authenticated KPM requests directly.
- `gummemory-green-payload.c` is the Gum memory seam; target writes are
  committed through KPM shadow, including code-page writes.
- `frida-java-bridge/` contains the reviewed bridge bundle and source notes.

The root `green` server creates a cryptographically random per-process token,
registers it with KPM, then sends it over the root-owned control socket. The
agent never creates or forwards privileged requests. Every PATCH, RELEASE, or
COUNT operation calls:

```c
prctl(PR_GREEN_SHADOW_REQUEST, token, &rpc, 0, 0);
```

There is no broker protocol in this payload.
