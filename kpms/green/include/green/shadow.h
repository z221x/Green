/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GREEN_CLI_SHADOW_H
#define GREEN_CLI_SHADOW_H

#include <stddef.h>
#include <sys/types.h>

int green_shadow_request_patch(pid_t pid, unsigned long addr,
                               const void *bytes, size_t len);
int green_shadow_request_release(pid_t pid, unsigned long addr);
long green_shadow_request_count(pid_t pid);
int green_shadow_make_branch(unsigned long pc, unsigned long target,
                             unsigned char out[4]);

#endif /* GREEN_CLI_SHADOW_H */
