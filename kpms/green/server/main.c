/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * `green` device binary: the frida-server equivalent.  Running it starts
 * the TCP daemon that owns the injector and token provisioning. The injected
 * agent calls KPM shadow directly; there is no page-operation broker. There
 * is intentionally no command-line tool surface on the device -- everything
 * is driven from the host Python CLI.
 */

#include <green/cli.h>
#include <green/wire.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int green_server_run(int listen_fd);

static void usage(const char *prog)
{
    fprintf(stderr,
            "green device server (frida-server equivalent)\n\n"
            "Usage:\n"
            "  %s [--port PORT]              (default %d, loopback only)\n\n"
            "All functionality is driven from the host CLI (cli/green.py):\n"
            "  adb forward tcp:%d tcp:%d\n",
            prog, GREEN_WIRE_DEFAULT_PORT, GREEN_WIRE_DEFAULT_PORT,
            GREEN_WIRE_DEFAULT_PORT);
}

int main(int argc, char **argv)
{
    int port = GREEN_WIRE_DEFAULT_PORT;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    return green_server_run(port);
}
