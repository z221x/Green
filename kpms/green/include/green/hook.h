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
 *   REQUEST: prctl(PR_GREEN_SHADOW_REQUEST, token, &green_shadow_rpc, 0, 0)
 *   REGISTER: prctl(PR_GREEN_SHADOW_TOKEN_REGISTER, pid, token, 0, 0)
 *   REVOKE:   prctl(PR_GREEN_SHADOW_TOKEN_REVOKE, pid, token, 0, 0)
 *
 * Every PATCH/RELEASE/COUNT request carries the token.  REGISTER and REVOKE
 * are root-only operations used to provision an injected agent; all actual
 * page operations are checked against the token bound to the target mm.
 *
 * Unlike the reference wxshadow module, Green's first implementation is
 * patch-oriented and intentionally has no BRK register-modification feature.
 */
extern const struct green_tool green_shadow_tool;

/* The KPM shadow engine has no unauthenticated public patch API. All page
 * operations enter through PR_GREEN_SHADOW_REQUEST with a registered token. */
long green_shadow_request(const struct green_shadow_rpc *rpc,
                          unsigned long token, bool caller_is_root);
long green_shadow_register_token(pid_t pid, unsigned long token);
long green_shadow_revoke_token(pid_t pid, unsigned long token);

#endif /* _KPM_GREEN_SHADOW_HOOK_H_ */
