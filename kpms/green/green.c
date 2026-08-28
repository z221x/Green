/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green.h>

#include <common.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>

KPM_NAME("kpm-green");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("z221x");
KPM_DESCRIPTION("Extensible ARM64 reverse-engineering toolkit");

static const struct green_tool *const green_tools[] = {
    &green_shadow_tool,
};

static int green_starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s++ != *prefix++)
            return 0;
    }
    return 1;
}

const struct green_tool *green_tool_find(const char *name)
{
    int i;

    if (!name)
        return 0;
    for (i = 0; i < (int)(sizeof(green_tools) / sizeof(green_tools[0])); i++) {
        int n = 0;

        while (green_tools[i]->name[n])
            n++;
        if (green_starts_with(name, green_tools[i]->name) && name[n] == '\0')
            return green_tools[i];
    }
    return 0;
}

static long green_copy_text(char __user *out_msg, int outlen, const char *text)
{
    int n = 0;

    if (!out_msg || outlen <= 0)
        return 0;

    while (n + 1 < outlen && text[n])
        n++;

    return compat_copy_to_user(out_msg, text, n + 1);
}

static long green_init(const char *args, const char *event, void __user *reserved)
{
    int i;
    long ret;

    pr_info("green: init event=%s args=%s\n", event ? event : "", args ? args : "");

    for (i = 0; i < (int)(sizeof(green_tools) / sizeof(green_tools[0])); i++) {
        const struct green_tool *tool = green_tools[i];

        if (!tool->init)
            continue;

        ret = tool->init(args, event, reserved);
        if (ret) {
            pr_err("green: tool %s init failed: %ld\n", tool->name, ret);
            while (--i >= 0) {
                if (green_tools[i]->exit)
                    green_tools[i]->exit(reserved);
            }
            return ret;
        }
        pr_info("green: tool %s ready\n", tool->name);
    }

    return 0;
}

static long green_control(const char *args, char __user *out_msg, int outlen)
{
    int i;

    if (!args || !args[0] || green_starts_with(args, "tools"))
        return green_copy_text(out_msg, outlen, "green tools: shadow");

    for (i = 0; i < (int)(sizeof(green_tools) / sizeof(green_tools[0])); i++) {
        const struct green_tool *tool = green_tools[i];
        const char *tail;
        int n = 0;

        while (tool->name[n])
            n++;

        if (!green_starts_with(args, tool->name))
            continue;

        tail = args + n;
        if (*tail && *tail != ' ')
            continue;
        if (*tail == ' ')
            tail++;
        if (tool->control)
            return tool->control(tail, out_msg, outlen);
        return green_copy_text(out_msg, outlen, "tool has no control handler");
    }

    return green_copy_text(out_msg, outlen, "unknown green tool");
}

static long green_exit(void __user *reserved)
{
    int i;

    pr_info("green: exit\n");
    for (i = (int)(sizeof(green_tools) / sizeof(green_tools[0])) - 1; i >= 0; i--) {
        if (green_tools[i]->exit)
            green_tools[i]->exit(reserved);
    }
    return 0;
}

KPM_INIT(green_init);
KPM_CTL0(green_control);
KPM_EXIT(green_exit);
