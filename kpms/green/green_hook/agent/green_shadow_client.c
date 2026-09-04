/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Direct authenticated client for the KPM shadow ABI.  This file deliberately
 * contains no socket/broker code: every page operation is one prctl carrying
 * the token issued by the root Green server. */

#include "green_agent.h"

#include <errno.h>
#include <sys/prctl.h>

static volatile unsigned long g_green_shadow_token;

void green_agent_set_shadow_token(unsigned long token)
{
    __atomic_store_n(&g_green_shadow_token, token, __ATOMIC_RELEASE);
}

unsigned long green_agent_get_shadow_token(void)
{
    return __atomic_load_n(&g_green_shadow_token, __ATOMIC_ACQUIRE);
}

int green_agent_shadow_request(unsigned int op, unsigned long addr,
                               const void *buf, unsigned long len,
                               long *value)
{
    struct green_shadow_rpc request;
    long ret;
    unsigned long token = green_agent_get_shadow_token();

    if (token == 0)
        return -EACCES;
    request.version = GREEN_SHADOW_ABI_VERSION;
    request.op = op;
    request.pid = 0;
    request.reserved = 0;
    request.addr = addr;
    request.buf = (unsigned long)buf;
    request.len = len;
    errno = 0;
    ret = prctl((int)PR_GREEN_SHADOW_REQUEST, token,
                (unsigned long)&request, 0, 0);
    if (ret < 0)
        return errno ? -errno : -EIO;
    if (value)
        *value = ret;
    return 0;
}
