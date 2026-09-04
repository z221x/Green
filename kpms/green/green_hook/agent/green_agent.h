/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_AGENT_H_
#define _GREEN_AGENT_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <green/abi.h>

#define GREEN_AGENT_MAGIC 0x31415247U /* "GRA1" */
#define GREEN_AGENT_VERSION 1U
#define GREEN_AGENT_SOCKET_PREFIX "green.agent."
#define GREEN_AGENT_SCRIPT_NAME "green_hook.js"

#define GREEN_AGENT_MAX_MESSAGE 128U
#define GREEN_AGENT_MAX_TOOLS 16U
#define GREEN_AGENT_STATUS_EVENT 0x7ffffffe

/* Tool and command identifiers are deliberately separate.  Future Green
 * tools can register another tool id without changing the transport. */
enum green_agent_tool_id {
    GREEN_AGENT_TOOL_CORE = 0,
    GREEN_AGENT_TOOL_GREEN_HOOK = 1,
    GREEN_AGENT_TOOL_JS = 2,
};

enum green_agent_js_command {
    GREEN_AGENT_CMD_JS_LOAD = 1, /* eval the script at the well-known path */
    GREEN_AGENT_CMD_JS_CALL = 2, /* call the probe; returns the hooked value */
    GREEN_AGENT_CMD_JS_EVAL = 3, /* evaluate response.arg0 as global JS code;
                                  * message carries the JSON result (truncated) */
};

enum green_agent_core_command {
    GREEN_AGENT_CMD_PING = 1,
    /* Root server provisions the KPM token over the authenticated control
     * socket.  The token is then attached to every direct shadow prctl. */
    GREEN_AGENT_CMD_SHADOW_TOKEN_SET = 3,
};

enum green_agent_hook_command {
    GREEN_AGENT_HOOK_REDIRECT = 1,
    GREEN_AGENT_HOOK_RELEASE = 2,
    GREEN_AGENT_HOOK_SELF_TEST = 3,
};

struct green_agent_request {
    uint32_t magic;
    uint16_t version;
    uint16_t tool;
    uint16_t command;
    uint16_t flags;
    uint32_t size;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

struct green_agent_response {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    int32_t status;
    uint32_t size;
    uint64_t value;
    char message[GREEN_AGENT_MAX_MESSAGE];
};

struct green_agent_tool;
typedef int (*green_agent_tool_handler)(const struct green_agent_request *request,
                                        struct green_agent_response *response,
                                        void *userdata);

typedef int (*green_agent_tool_register)(const struct green_agent_tool *tool);

struct green_agent_tool {
    uint16_t id;
    const char *name;
    green_agent_tool_handler handler;
    void *userdata;
};

/* The name excludes the leading NUL required by an abstract AF_UNIX address. */
static inline int green_agent_socket_name(pid_t pid, char *out, size_t out_size)
{
    int n;

    if (!out || out_size == 0 || pid <= 0)
        return -1;
    n = snprintf(out, out_size, GREEN_AGENT_SOCKET_PREFIX "%d", (int)pid);
    return n < 0 || (size_t)n >= out_size ? -1 : n;
}

/* Token lifecycle and direct authenticated shadow calls. */
void green_agent_set_shadow_token(unsigned long token);
unsigned long green_agent_get_shadow_token(void);
int green_agent_shadow_request(unsigned int op, unsigned long addr,
                               const void *buf, unsigned long len,
                               long *value);

#endif /* _GREEN_AGENT_H_ */
