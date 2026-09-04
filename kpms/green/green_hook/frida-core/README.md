# Green Frida core boundary

`frida-core` is reserved for the host-side Frida compatibility boundary. The
current transport is documented in `kpms/green/include/green/wire.h`; it
carries Frida-style process, attach, script, evaluation, and log operations to
the on-device `green` server.

The injected runtime is stock Frida GumJS (`vendor/frida-gum`) and is not
reimplemented here. Green-specific behavior is limited to the KPM shadow
memory backend and token provisioning.
