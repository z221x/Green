/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_AGENT_H_
#define _GREEN_AGENT_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define GREEN_AGENT_MAGIC 0x31415247U /* "GRA1" */
#define GREEN_AGENT_VERSION 1U
#define GREEN_AGENT_SOCKET_PREFIX "green.agent."
#define GREEN_AGENT_BROKER_PREFIX "green.broker."

#define GREEN_AGENT_MAX_MESSAGE 128U
#define GREEN_AGENT_MAX_TOOLS 16U

/* Tool and command identifiers are deliberately separate.  Future Green
 * tools can register another tool id without changing the transport. */
enum green_agent_tool_id {
    GREEN_AGENT_TOOL_CORE = 0,
    GREEN_AGENT_TOOL_GREEN_HOOK = 1,
};

enum green_agent_core_command {
    GREEN_AGENT_CMD_PING = 1,
    GREEN_AGENT_CMD_STATUS = 2,
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

/* Broker protocol: the agent has no kernel privileges and never calls the
 * Green prctl ABI itself.  A root-side `green shadow broker` listens on
 * @green.broker.<target-pid>, and the agent forwards privileged page-table
 * operations (patch/release/count) to it. */
enum green_broker_command {
    GREEN_BROKER_PATCH = 1,
    GREEN_BROKER_RELEASE = 2,
    GREEN_BROKER_COUNT = 3,
};

struct green_broker_request {
    uint32_t magic;
    uint32_t command;
    uint64_t addr;
    uint32_t len; /* payload bytes after this header (PATCH only) */
    uint32_t reserved;
};

struct green_broker_response {
    int32_t status; /* 0 on success, -errno otherwise */
    uint32_t reserved;
    int64_t value;
};

static inline int green_agent_broker_name(pid_t pid, char *out, size_t out_size)
{
    int n;

    if (!out || out_size == 0 || pid <= 0)
        return -1;
    n = snprintf(out, out_size, GREEN_AGENT_BROKER_PREFIX "%d", (int)pid);
    return n < 0 || (size_t)n >= out_size ? -1 : n;
}

#endif /* _GREEN_AGENT_H_ */
