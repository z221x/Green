/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * `green hook`: on-device helper that attaches to a target process and runs
 * a QuickJS hook script.  The same flow is available from a host machine
 * through `green server` + the Python CLI; this command exists for
 * debugging directly on the device.
 *
 *   green hook attach (-f <package> | -p <pid>) (-l <script.js> | -c "<js>")
 *   green hook spawn <package>          (reserved, not implemented)
 */

#include <green/agentops.h>
#include <green/cli.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void hook_usage(const char *prog)
{
    fprintf(stderr,
            "Green hook: attach a target and run a QuickJS hook script\n\n"
            "Usage:\n"
            "  %s attach -f <package> -l <script.js>\n"
            "  %s attach -p <pid> -l <script.js>\n"
            "  %s attach -p <pid> -c \"<js code>\"\n"
            "  %s spawn <package>          (not implemented yet)\n\n"
            "Options:\n"
            "  -f <package>   target Android package (running process)\n"
            "  -p <pid>       target pid\n"
            "  -l <script.js> hook script file (device path)\n"
            "  -c \"<js code>\"  inline hook script\n\n"
            "Push the payload first: adb push libgreen_agent.so %s\n",
            prog, prog, prog, prog, GREEN_AGENT_SO_SOURCE);
}

int green_hook_main(int argc, char **argv)
{
    const char *command;
    const char *package = NULL;
    const char *script_file = NULL;
    const char *inline_code = NULL;
    unsigned long pid_value = 0;
    int i;

    if (argc < 2) {
        hook_usage(argv[0]);
        return 1;
    }
    command = argv[1];

    if (!strcmp(command, "spawn")) {
        if (argc < 3) {
            hook_usage(argv[0]);
            return 2;
        }
        fprintf(stderr, "hook: spawn %s is not implemented yet\n", argv[2]);
        return 2;
    }

    if (strcmp(command, "attach") != 0) {
        hook_usage(argv[0]);
        return 2;
    }

    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc)
            package = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            green_cli_parse_pid(argv[++i], (pid_t *)&pid_value);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc)
            script_file = argv[++i];
        else if (!strcmp(argv[i], "-c") && i + 1 < argc)
            inline_code = argv[++i];
        else {
            hook_usage(argv[0]);
            return 2;
        }
    }

    if ((pid_value == 0) == (package == NULL)) {
        fprintf(stderr, "hook: attach needs exactly one of -f/-p\n");
        return 2;
    }
    if ((script_file == NULL) == (inline_code == NULL)) {
        fprintf(stderr, "hook: attach needs exactly one of -l/-c\n");
        return 2;
    }
    if (package) {
        pid_t pid = green_agentops_find_package(package);

        if (pid <= 0) {
            fprintf(stderr, "hook: no running process for %s\n", package);
            return 1;
        }
        pid_value = (unsigned long)pid;
        fprintf(stderr, "hook: %s -> pid %ld\n", package, (long)pid_value);
    }

    return green_agentops_attach_and_load((pid_t)pid_value, script_file,
                                          inline_code);
}

const struct green_cli_tool green_cli_hook_tool = {
    .name = "hook",
    .summary = "attach a target and run a QuickJS hook script (on-device)",
    .main = green_hook_main,
    .usage = hook_usage,
};
