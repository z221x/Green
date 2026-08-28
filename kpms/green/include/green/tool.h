/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_GREEN_TOOL_H_
#define _KPM_GREEN_TOOL_H_

#include <compiler.h>
#include <ktypes.h>

struct green_tool {
    const char *name;
    long (*init)(const char *args, const char *event, void __user *reserved);
    long (*control)(const char *args, char __user *out_msg, int outlen);
    long (*exit)(void __user *reserved);
};

/* Public registry lookup so tools can compose without depending on green.c. */
const struct green_tool *green_tool_find(const char *name);

#endif /* _KPM_GREEN_TOOL_H_ */
