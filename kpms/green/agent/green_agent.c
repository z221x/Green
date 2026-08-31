/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * In-process Green agent.
 *
 * This is the payload loaded into a target process.  It intentionally contains
 * only transport and dispatch glue; Green hook implementation stays in
 * green_hook/.  New tools can register another handler through the small
 * registry instead of growing the injector protocol.
 */
#include "green_agent.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <unistd.h>

#include <green/abi.h>
#include <gum/arch-arm64/gumarm64writer.h>
#include <gum/gummemory.h>

#include "green_gum.h"

struct green_agent_registry {
    pthread_mutex_t lock;
    struct green_agent_tool tools[GREEN_AGENT_MAX_TOOLS];
    size_t count;
};

static struct green_agent_registry green_agent_registry = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};
static pthread_once_t green_agent_once = PTHREAD_ONCE_INIT;
static int green_agent_server_fd = -1;

static int green_agent_read_full(int fd, void *buf, size_t size)
{
    size_t done = 0;

    while (done < size) {
        ssize_t n = read(fd, (char *)buf + done, size - done);
        if (n == 0)
            return -1;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static int green_agent_write_full(int fd, const void *buf, size_t size)
{
    size_t done = 0;

    while (done < size) {
        ssize_t n = write(fd, (const char *)buf + done, size - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

int green_agent_register_tool(const struct green_agent_tool *tool)
{
    size_t i;

    if (!tool || !tool->handler || tool->id == GREEN_AGENT_TOOL_CORE)
        return -EINVAL;

    pthread_mutex_lock(&green_agent_registry.lock);
    for (i = 0; i < green_agent_registry.count; i++) {
        if (green_agent_registry.tools[i].id == tool->id) {
            pthread_mutex_unlock(&green_agent_registry.lock);
            return -EEXIST;
        }
    }
    if (green_agent_registry.count == GREEN_AGENT_MAX_TOOLS) {
        pthread_mutex_unlock(&green_agent_registry.lock);
        return -ENOSPC;
    }
    green_agent_registry.tools[green_agent_registry.count++] = *tool;
    pthread_mutex_unlock(&green_agent_registry.lock);
    return 0;
}

static void green_agent_redirect_apply(gpointer memory, gpointer user_data)
{
    GumArm64Writer writer;
    guint64 replacement = (guint64)(uintptr_t)user_data;

    gum_arm64_writer_init(&writer, memory);
    writer.pc = (GumAddress)(uintptr_t)memory;
    gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16, replacement);
    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);
}

static int green_agent_hook_self_test(struct green_agent_response *response);

static int green_agent_hook_handler(const struct green_agent_request *request,
                                    struct green_agent_response *response,
                                    void *userdata)
{
    gboolean ok;

    (void)userdata;
    if (request->command == GREEN_AGENT_HOOK_REDIRECT) {
        if ((request->arg0 & 3) != 0 || (request->arg1 & 3) != 0 ||
            request->arg2 < 16 || request->arg2 > 4096)
            return -EINVAL;
        ok = gum_memory_patch_code((gpointer)(uintptr_t)request->arg0,
                                    (gsize)request->arg2,
                                    green_agent_redirect_apply,
                                    (gpointer)(uintptr_t)request->arg1);
        if (!ok)
            return -EIO;
        response->value = request->arg0;
        return 0;
    }

    if (request->command == GREEN_AGENT_HOOK_RELEASE) {
        if (!green_gum_release_page((gconstpointer)(uintptr_t)request->arg0))
            return -EIO;
        response->value = request->arg0 & ~4095ULL;
        return 0;
    }

    if (request->command == GREEN_AGENT_HOOK_SELF_TEST)
        return green_agent_hook_self_test(response);

    return -EOPNOTSUPP;
}

__attribute__((noinline)) static int green_agent_test_target(int value)
{
    asm volatile("" ::: "memory");
    return value + 1;
}

__attribute__((noinline)) static int green_agent_test_replacement(int value)
{
    asm volatile("" ::: "memory");
    return value + 100;
}

static int green_agent_hook_self_test(struct green_agent_response *response)
{
    int before;
    int during;

    before = green_agent_test_target(1);
    if (before != 2)
        return -EFAULT;
    if (!gum_memory_patch_code((gpointer)(uintptr_t)green_agent_test_target,
                               16, green_agent_redirect_apply,
                               (gpointer)(uintptr_t)green_agent_test_replacement))
        return -EIO;
    during = green_agent_test_target(1);
    if (during != 101) {
        green_gum_release_page((gconstpointer)green_agent_test_target);
        return -EFAULT;
    }
    if (!green_gum_release_page((gconstpointer)green_agent_test_target))
        return -EIO;
    response->value = (uint64_t)((before << 16) | during);
    snprintf(response->message, sizeof(response->message),
             "green_hook self-test before=%d during=%d after=%d", before,
             during, green_agent_test_target(1));
    return green_agent_test_target(1) == 2 ? 0 : -EFAULT;
}

static const struct green_agent_tool green_agent_hook_tool = {
    .id = GREEN_AGENT_TOOL_GREEN_HOOK,
    .name = "green_hook",
    .handler = green_agent_hook_handler,
};

static void green_agent_response_init(struct green_agent_response *response)
{
    memset(response, 0, sizeof(*response));
    response->magic = GREEN_AGENT_MAGIC;
    response->version = GREEN_AGENT_VERSION;
    response->size = sizeof(*response);
}

static int green_agent_core_dispatch(const struct green_agent_request *request,
                                     struct green_agent_response *response)
{
    long count;

    if (request->command == GREEN_AGENT_CMD_PING) {
        response->value = (uint64_t)getpid();
        snprintf(response->message, sizeof(response->message),
                 "green-agent ready pid=%d", (int)getpid());
        return 0;
    }
    if (request->command == GREEN_AGENT_CMD_STATUS) {
        count = prctl((int)PR_GREEN_SHADOW_COUNT, 0, 0, 0, 0);
        response->value = count >= 0 ? (uint64_t)count : 0;
        snprintf(response->message, sizeof(response->message),
                 "green-agent pid=%d shadow_count=%ld", (int)getpid(), count);
        return count < 0 ? -errno : 0;
    }
    return -EOPNOTSUPP;
}

static int green_agent_peer_uid(int fd, uid_t *uid)
{
    struct ucred cred;
    socklen_t size = sizeof(cred);

    if (!uid || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) != 0)
        return -1;
    *uid = cred.uid;
    return 0;
}

static int green_agent_dispatch(int fd, const struct green_agent_request *request,
                                struct green_agent_response *response)
{
    size_t i;
    uid_t uid;
    int status;

    if (request->tool == GREEN_AGENT_TOOL_CORE)
        return green_agent_core_dispatch(request, response);

    /* Mutating target memory is a root-controller operation.  The injected
     * process itself is normally an unprivileged Android app. */
    if (green_agent_peer_uid(fd, &uid) != 0 || uid != 0)
        return -EPERM;

    pthread_mutex_lock(&green_agent_registry.lock);
    for (i = 0; i < green_agent_registry.count; i++) {
        if (green_agent_registry.tools[i].id != request->tool)
            continue;
        green_agent_tool_handler handler = green_agent_registry.tools[i].handler;
        void *userdata = green_agent_registry.tools[i].userdata;
        pthread_mutex_unlock(&green_agent_registry.lock);
        status = handler(request, response, userdata);
        return status;
    }
    pthread_mutex_unlock(&green_agent_registry.lock);
    return -ENOENT;
}

static void *green_agent_server_main(void *unused)
{
    struct sockaddr_un address;
    char name[sizeof(address.sun_path) - 1];
    size_t name_len;

    (void)unused;
    green_agent_socket_name(getpid(), name, sizeof(name));
    name_len = strlen(name);

    green_agent_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (green_agent_server_fd < 0)
        return NULL;

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, name_len);
    if (bind(green_agent_server_fd, (struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len)) != 0 ||
        listen(green_agent_server_fd, 4) != 0) {
        close(green_agent_server_fd);
        green_agent_server_fd = -1;
        return NULL;
    }

    for (;;) {
        int client = accept(green_agent_server_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (;;) {
            struct green_agent_request request;
            struct green_agent_response response;
            int status;

            if (green_agent_read_full(client, &request, sizeof(request)) != 0)
                break;
            green_agent_response_init(&response);
            if (request.magic != GREEN_AGENT_MAGIC ||
                request.version != GREEN_AGENT_VERSION ||
                request.size != sizeof(request)) {
                status = -EPROTO;
            } else {
                status = green_agent_dispatch(client, &request, &response);
            }
            response.status = status;
            if (status != 0 && response.message[0] == '\0')
                snprintf(response.message, sizeof(response.message),
                         "agent command failed: %d", status);
            if (green_agent_write_full(client, &response, sizeof(response)) != 0)
                break;
        }
        close(client);
    }
    return NULL;
}

static void green_agent_start_once(void)
{
    pthread_t thread;
    struct sigaction ignored;

    green_agent_register_tool(&green_agent_hook_tool);
    memset(&ignored, 0, sizeof(ignored));
    ignored.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &ignored, NULL);
    if (pthread_create(&thread, NULL, green_agent_server_main, NULL) == 0)
        pthread_detach(thread);
}

__attribute__((constructor)) static void green_agent_constructor(void)
{
    pthread_once(&green_agent_once, green_agent_start_once);
}
