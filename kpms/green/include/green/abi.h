/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_ABI_H_
#define _GREEN_ABI_H_

#define PR_GREEN_SHADOW_BASE             0x47524800UL /* "GRH" */

/*
 * Shadow access is deliberately a single authenticated request path.  The
 * old PATCH/RELEASE/COUNT ABI allowed a root controller to act on behalf of
 * an application and forced the payload through a broker socket.  The new
 * ABI carries the token as a prctl argument on every request and is callable
 * directly from the injected process.
 */
#define PR_GREEN_SHADOW_REQUEST          (PR_GREEN_SHADOW_BASE + 1)
#define PR_GREEN_SHADOW_TOKEN_REGISTER   (PR_GREEN_SHADOW_BASE + 2)
#define PR_GREEN_SHADOW_TOKEN_REVOKE     (PR_GREEN_SHADOW_BASE + 3)

#define GREEN_SHADOW_ABI_VERSION         1U

enum green_shadow_request_op {
    GREEN_SHADOW_OP_PATCH = 1,
    GREEN_SHADOW_OP_RELEASE = 2,
    GREEN_SHADOW_OP_COUNT = 3,
};

/* All fields are naturally 64-bit aligned on the supported arm64 ABI. */
struct green_shadow_rpc {
    unsigned int version;
    unsigned int op;
    int pid;                    /* 0 = caller's mm */
    unsigned int reserved;
    unsigned long addr;
    unsigned long buf;          /* caller address, PATCH only */
    unsigned long len;          /* PATCH length */
};

#define GREEN_SHADOW_MAX_PATCH_LEN 4096UL

#endif /* _GREEN_ABI_H_ */
