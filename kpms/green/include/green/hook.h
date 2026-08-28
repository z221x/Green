/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_GREEN_SHADOW_HOOK_H_
#define _KPM_GREEN_SHADOW_HOOK_H_

#include <compiler.h>
#include <ktypes.h>
#include <green/abi.h>
#include <green/tool.h>

/*
 * Green shadow hook ABI.
 *
 * The prctl arguments are:
 *   PATCH:   prctl(PR_GREEN_SHADOW_PATCH,   pid, addr, user_buf, len)
 *   RELEASE: prctl(PR_GREEN_SHADOW_RELEASE, pid, addr, 0, 0)
 *            addr == 0 releases all shadow pages that belong to pid.
 *   COUNT:   prctl(PR_GREEN_SHADOW_COUNT,   pid, 0, 0, 0)
 *
 * Unlike the reference wxshadow module, Green's first implementation is
 * patch-oriented and intentionally has no BRK register-modification feature.
 */
struct green_shadow_request {
    pid_t pid;
    unsigned long addr;
    const void __user *buf;
    unsigned long len;
};

extern const struct green_tool green_shadow_tool;

/* Kernel-side API usable by future Green tools. */
long green_shadow_patch_task(pid_t pid, unsigned long addr,
                             const void __user *buf, unsigned long len);
long green_shadow_patch_kernel(pid_t pid, unsigned long addr,
                               const void *buf, unsigned long len);
long green_shadow_release_task(pid_t pid, unsigned long addr);
long green_shadow_count_task(pid_t pid);

#endif /* _KPM_GREEN_SHADOW_HOOK_H_ */
