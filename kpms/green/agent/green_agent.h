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
    /* Root connects to the agent socket and attaches as the broker; the
     * agent then forwards privileged page-table requests over that
     * connection.  (SELinux forbids untrusted_app -> root connectto, so the
     * connection must be established by root.) */
    GREEN_AGENT_CMD_BROKER_ATTACH = 3,
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
 * Green prctl ABI itself.  The root controller attaches a dedicated
 * connection to @green.agent.<target-pid>, and the agent forwards privileged
 * page-table operations (patch/release/count) over that connection. */
enum green_broker_command {
    GREEN_BROKER_PATCH = 1,
    GREEN_BROKER_RELEASE = 2,
    GREEN_BROKER_COUNT = 3,
    /* Agent -> server, one-way (never answered): script console output and
     * send() payloads; len bytes of UTF-8 text follow the header. */
    GREEN_BROKER_LOG = 4,
    /* Interceptor.attach: addr = target; a green_hook_attach_req follows. */
    GREEN_BROKER_HOOK_ATTACH = 6,
};

/* Interceptor.attach support: the server relocates the target's prologue
 * into the caller-provided r-x slot and redirects the entry to it via the
 * slot dispatch stub (which publishes hook_id through id_addr). */
struct green_hook_attach_req {
    uint64_t slot;         /* r-x slot page in the target */
    uint64_t shared_tramp; /* payload shared attach trampoline */
    uint64_t id_addr;      /* payload u32 global receiving the hook id */
    uint32_t hook_id;
    uint32_t reserved;
};

struct green_broker_request {
    uint32_t magic;
    uint32_t command;
    uint64_t addr; /* PATCH: target/page address; RELEASE: page address */
    uint64_t arg;  /* PATCH, len==0: replacement address */
    uint32_t len;  /* PATCH image bytes following this header (0..4096);
                    * len==0 means the broker snapshots the page itself */
    uint32_t reserved;
};

struct green_broker_response {
    int32_t status; /* 0 on success, -errno otherwise */
    uint32_t reserved;
    int64_t value;
};

/* Called by the vendored gum memory backend to commit a page image to the
 * shadow copy through the root-side broker.  Implemented by the transport. */
int green_agent_broker_page_commit(uint64_t page_address,
                                   const void *image, size_t len);

static inline int green_agent_broker_name(pid_t pid, char *out, size_t out_size)
{
    int n;

    if (!out || out_size == 0 || pid <= 0)
        return -1;
    n = snprintf(out, out_size, GREEN_AGENT_BROKER_PREFIX "%d", (int)pid);
    return n < 0 || (size_t)n >= out_size ? -1 : n;
}

#endif /* _GREEN_AGENT_H_ */
