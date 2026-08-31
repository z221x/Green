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
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/un.h>
#include <unistd.h>

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

static int green_agent_broker_request(uint32_t command, uint64_t addr,
                                      const void *payload, uint32_t len,
                                      int64_t *value)
{
    struct sockaddr_un address;
    struct green_broker_request request;
    struct green_broker_response response;
    char name[sizeof(address.sun_path) - 1];
    int fd;
    int name_len;

    name_len = green_agent_broker_name(getpid(), name, sizeof(name));
    if (name_len < 0)
        return -EINVAL;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -errno;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, (size_t)name_len);
    if (connect(fd, (struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len)) != 0) {
        close(fd);
        return -ENOENT;
    }

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.command = command;
    request.addr = addr;
    request.len = len;
    if (write(fd, &request, sizeof(request)) != (ssize_t)sizeof(request) ||
        (len != 0 && write(fd, payload, len) != (ssize_t)len) ||
        read(fd, &response, sizeof(response)) != (ssize_t)sizeof(response)) {
        close(fd);
        return -EIO;
    }
    close(fd);
    if (value)
        *value = response.value;
    return response.status;
}

static int green_agent_hook_self_test(struct green_agent_response *response);

/* Prepare the patched page image locally: snapshot this process's original
 * page through process_vm_readv, then let the real GumArm64Writer emit the
 * redirect into the snapshot.  The privileged commit itself is forwarded to
 * the root-side broker. */
static int green_agent_hook_redirect(uint64_t target, uint64_t replacement,
                                     struct green_agent_response *response)
{
    uint64_t page = target & ~4095ULL;
    size_t offset = (size_t)(target - page);
    guint8 *snapshot;
    GumArm64Writer writer;
    guint64 replacement_addr = (guint64)replacement;
    int status;

    if ((target & 3) != 0 || (replacement & 3) != 0 || offset > 4096 - 16)
        return -EINVAL;

    snapshot = malloc(4096);
    if (!snapshot)
        return -ENOMEM;
    {
        struct iovec local = { .iov_base = snapshot, .iov_len = 4096 };
        struct iovec remote = { .iov_base = (void *)(uintptr_t)page,
                                .iov_len = 4096 };
        ssize_t n;

        do {
            n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        } while (n < 0 && errno == EINTR);
        if (n != 4096) {
            free(snapshot);
            return -EIO;
        }
    }

    gum_arm64_writer_init(&writer, snapshot + offset);
    writer.pc = (GumAddress)target;
    gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16,
                                         replacement_addr);
    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);

    status = green_agent_broker_request(GREEN_BROKER_PATCH, page, snapshot,
                                        4096, &response->value);
    free(snapshot);
    if (status != 0)
        return status ? status : -EIO;
    response->value = target;
    return 0;
}

static int green_agent_hook_handler(const struct green_agent_request *request,
                                    struct green_agent_response *response,
                                    void *userdata)
{
    int64_t value = 0;
    int status;

    (void)userdata;
    switch (request->command) {
    case GREEN_AGENT_HOOK_REDIRECT:
        status = green_agent_hook_redirect(request->arg0, request->arg1,
                                           response);
        return status;

    case GREEN_AGENT_HOOK_RELEASE:
        status = green_agent_broker_request(GREEN_BROKER_RELEASE,
                                            request->arg0 & ~4095ULL, NULL,
                                            0, &value);
        if (status != 0)
            return status;
        response->value = request->arg0 & ~4095ULL;
        return 0;

    case GREEN_AGENT_HOOK_SELF_TEST:
        return green_agent_hook_self_test(response);

    default:
        return -EOPNOTSUPP;
    }
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
    struct green_agent_response unused;
    int before;
    int during;
    int status;

    memset(&unused, 0, sizeof(unused));
    before = green_agent_test_target(1);
    if (before != 2)
        return -EFAULT;

    status = green_agent_hook_redirect(
        (uint64_t)(uintptr_t)green_agent_test_target,
        (uint64_t)(uintptr_t)green_agent_test_replacement, &unused);
    if (status != 0)
        return status;

    during = green_agent_test_target(1);
    if (during != 101) {
        green_agent_broker_request(GREEN_BROKER_RELEASE,
                                   (uint64_t)(uintptr_t)green_agent_test_target &
                                       ~4095ULL,
                                   NULL, 0, NULL);
        return -EFAULT;
    }

    status = green_agent_broker_request(
        GREEN_BROKER_RELEASE,
        (uint64_t)(uintptr_t)green_agent_test_target & ~4095ULL, NULL, 0,
        NULL);
    if (status != 0)
        return status;

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
    if (request->command == GREEN_AGENT_CMD_PING) {
        response->value = (uint64_t)getpid();
        snprintf(response->message, sizeof(response->message),
                 "green-agent ready pid=%d", (int)getpid());
        return 0;
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
