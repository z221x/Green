/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/cli.h>

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const struct green_cli_tool *tool;

    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        green_cli_global_usage(argv[0]);
        return argc < 2 ? 1 : 0;
    }

    tool = green_cli_find_tool(argv[1]);
    if (tool)
        return tool->main(argc - 1, argv + 1);

    fprintf(stderr, "unknown tool: %s\n\n", argv[1]);
    green_cli_global_usage(argv[0]);
    return 1;
}
