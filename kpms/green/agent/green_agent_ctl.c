/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Root-side Green agent controller.
 *
 * `inject` attaches to one AArch64 thread, calls the target's dlopen() with
 * the payload path, restores all registers, and detaches.  The controller
 * then talks to the payload over its per-pid abstract Unix socket.
 */
#include "green_agent.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>

#include <green/abi.h>
#include <sys/prctl.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <sys/uio.h>

#include <gum/arch-arm64/gumarm64writer.h>
#include <sys/wait.h>
#include <unistd.h>

struct map_entry {
    uintptr_t start;
    uintptr_t end;
    unsigned long offset;
    char perms[5];
    char path[512];
};

static int parse_map_line(const char *line, struct map_entry *entry)
{
    unsigned long long start, end, offset;
    int consumed = 0;

    memset(entry, 0, sizeof(*entry));
    if (sscanf(line, "%llx-%llx %4s %llx %*s %*s %n",
               &start, &end, entry->perms, &offset, &consumed) < 4)
        return -1;
    entry->start = (uintptr_t)start;
    entry->end = (uintptr_t)end;
    entry->offset = (unsigned long)offset;
    if (line[consumed] != '\0') {
        while (line[consumed] == ' ' || line[consumed] == '\t')
            consumed++;
        snprintf(entry->path, sizeof(entry->path), "%s", line + consumed);
        entry->path[strcspn(entry->path, "\n")] = '\0';
    }
    return 0;
}

static int find_map_containing(pid_t pid, uintptr_t address,
                               struct map_entry *out)
{
    char path[64];
    char line[1024];
    FILE *maps;

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    maps = fopen(path, "re");
    if (!maps)
        return -1;
    while (fgets(line, sizeof(line), maps)) {
        struct map_entry entry;
        if (parse_map_line(line, &entry) == 0 &&
            address >= entry.start && address < entry.end) {
            *out = entry;
            fclose(maps);
            return 0;
        }
    }
    fclose(maps);
    return -1;
}

static int find_stack(pid_t pid, struct map_entry *out)
{
    char path[64];
    char line[1024];
    FILE *maps;

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    maps = fopen(path, "re");
    if (!maps)
        return -1;
    while (fgets(line, sizeof(line), maps)) {
        struct map_entry entry;
        if (parse_map_line(line, &entry) == 0 &&
            !strncmp(entry.path, "[stack", 6) &&
            entry.perms[0] == 'r' && entry.perms[1] == 'w') {
            *out = entry;
            fclose(maps);
            return 0;
        }
    }
    fclose(maps);
    return -1;
}

static const char *map_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int find_target_library_map(pid_t pid, const struct map_entry *local,
                                   struct map_entry *target)
{
    char path[64];
    char line[1024];
    FILE *maps;
    const char *base = map_basename(local->path);

    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    maps = fopen(path, "re");
    if (!maps)
        return -1;
    while (fgets(line, sizeof(line), maps)) {
        struct map_entry entry;
        if (parse_map_line(line, &entry) != 0)
            continue;
        if (entry.offset != local->offset || entry.perms[2] != 'x' ||
            strcmp(map_basename(entry.path), base) != 0)
            continue;
        *target = entry;
        fclose(maps);
        return 0;
    }
    fclose(maps);
    return -1;
}

static int get_regs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS,
                  &iov);
}

static int set_regs(pid_t pid, const struct user_pt_regs *regs)
{
    struct iovec iov = { .iov_base = (void *)regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS,
                  &iov);
}

static int remote_write(pid_t pid, uintptr_t address, const void *data,
                        size_t size)
{
    struct iovec local = { .iov_base = (void *)data, .iov_len = size };
    struct iovec remote = { .iov_base = (void *)address, .iov_len = size };
    ssize_t n;

    n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)size)
        return 0;

    /* Fallback for kernels that restrict process_vm_writev even after attach. */
    while (size != 0) {
        uintptr_t aligned = address & ~(sizeof(long) - 1);
        unsigned long word = 0;
        size_t offset = address - aligned;
        size_t chunk = sizeof(word) - offset;

        if (chunk > size)
            chunk = size;
        errno = 0;
        if (offset != 0 || chunk != sizeof(word)) {
            long old = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned, NULL);
            if (old == -1 && errno != 0)
                return -1;
            word = (unsigned long)old;
        }
        memcpy((char *)&word + offset, data, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)aligned,
                   (void *)word) != 0)
            return -1;
        address += chunk;
        data = (const char *)data + chunk;
        size -= chunk;
    }
    return 0;
}

static int wait_initial_stop(pid_t pid)
{
    int status;

    if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status))
        return -1;
    return 0;
}

static int remote_dlopen(pid_t pid, const char *payload)
{
    struct user_pt_regs saved;
    struct user_pt_regs call;
    struct map_entry local_map;
    struct map_entry target_map;
    struct map_entry stack;
    void *local_dlopen;
    uintptr_t remote_dlopen;
    uintptr_t remote_path;
    size_t payload_len = strlen(payload) + 1;
    int status;
    int result = -1;

    local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen || find_map_containing(getpid(), (uintptr_t)local_dlopen,
                                             &local_map) != 0 ||
        find_target_library_map(pid, &local_map, &target_map) != 0 ||
        find_stack(pid, &stack) != 0) {
        fprintf(stderr, "cannot resolve target dlopen/stack\n");
        return -1;
    }

    remote_dlopen = target_map.start +
        ((uintptr_t)local_dlopen - local_map.start);
    remote_path = (stack.end - 0x1000 - payload_len) & ~(uintptr_t)0xf;
    if (remote_write(pid, remote_path, payload, payload_len) != 0) {
        perror("write remote payload path");
        return -1;
    }
    if (get_regs(pid, &saved) != 0)
        return -1;
    call = saved;
    call.regs[0] = remote_path;
    call.regs[1] = RTLD_NOW | RTLD_GLOBAL;
    call.sp = remote_path & ~(uintptr_t)0xf;
    call.regs[30] = 0; /* return to address 0; ptrace catches SIGSEGV */
    call.pc = remote_dlopen;
    if (set_regs(pid, &call) != 0)
        return -1;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0)
        goto restore;
    for (;;) {
        if (waitpid(pid, &status, __WALL) != pid)
            goto restore;
        if (!WIFSTOPPED(status))
            goto restore;
        if (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGBUS) {
            struct user_pt_regs after;
            if (get_regs(pid, &after) == 0 && after.pc == 0) {
                result = after.regs[0] != 0 ? 0 : -1;
            }
            break;
        }
        if (ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)WSTOPSIG(status)) != 0)
            break;
    }

restore:
    if (set_regs(pid, &saved) != 0)
        result = -1;
    return result;
}

static int inject_payload(pid_t pid, const char *payload)
{
    int attached = 0;
    int result = -1;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        goto disable;
    }
    attached = 1;
    if (wait_initial_stop(pid) != 0) {
        fprintf(stderr, "target did not stop\n");
        goto detach;
    }
    result = remote_dlopen(pid, payload);

detach:
    if (attached)
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (result != 0)
        goto disable;
    return 0;

disable:
    return -1;
}

/* Broker mode: attach to the agent as root, then serve the agent's
 * privileged page-table requests (snapshot + writer + prctl). */
static int broker_serve(pid_t pid)
{
    struct sockaddr_un address;
    struct green_agent_request request;
    struct green_agent_response response;
    char name[sizeof(address.sun_path) - 1];
    int fd;
    int name_len;

    name_len = green_agent_socket_name(pid, name, sizeof(name));
    if (name_len < 0)
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, (size_t)name_len);
    if (connect(fd, (struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len)) != 0) {
        perror("connect agent");
        close(fd);
        return -1;
    }

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = GREEN_AGENT_TOOL_CORE;
    request.command = GREEN_AGENT_CMD_BROKER_ATTACH;
    request.size = sizeof(request);
    if (write(fd, &request, sizeof(request)) != (ssize_t)sizeof(request) ||
        read(fd, &response, sizeof(response)) != (ssize_t)sizeof(response) ||
        response.status != 0) {
        fprintf(stderr, "broker attach failed\n");
        close(fd);
        return -1;
    }
    printf("broker attached to pid %d\n", (int)pid);
    fflush(stdout);

    for (;;) {
        struct green_broker_request request;
        struct green_broker_response response;
        static guint8 snapshot[4096];
        long pr = 0;

        if (read(fd, &request, sizeof(request)) != (ssize_t)sizeof(request))
            break;
        memset(&response, 0, sizeof(response));
        if (request.magic != GREEN_AGENT_MAGIC) {
            response.status = -EBADMSG;
        } else if (request.command == GREEN_BROKER_PATCH) {
            unsigned long page = request.addr & ~4095UL;
            size_t offset = (size_t)(request.addr - page);
            struct iovec local = { .iov_base = snapshot,
                                   .iov_len = sizeof(snapshot) };
            struct iovec remote = { .iov_base = (void *)page,
                                    .iov_len = sizeof(snapshot) };
            GumArm64Writer writer;
            ssize_t n;

            if ((request.addr & 3) || (request.arg & 3) || offset > 4096 - 16) {
                response.status = -EINVAL;
            } else {
                do {
                    n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
                } while (n < 0 && errno == EINTR);
                if (n != (ssize_t)sizeof(snapshot)) {
                    response.status = -EIO;
                } else {
                    gum_arm64_writer_init(&writer, snapshot + offset);
                    writer.pc = (GumAddress)request.addr;
                    gum_arm64_writer_put_ldr_reg_address(
                        &writer, ARM64_REG_X16, (guint64)request.arg);
                    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
                    gum_arm64_writer_flush(&writer);
                    gum_arm64_writer_clear(&writer);
                    pr = prctl((int)PR_GREEN_SHADOW_PATCH, (unsigned long)pid,
                               page, (unsigned long)snapshot,
                               sizeof(snapshot));
                    response.status = pr < 0 ? -(int)errno : 0;
                    response.value = pr;
                }
            }
        } else if (request.command == GREEN_BROKER_RELEASE) {
            pr = prctl((int)PR_GREEN_SHADOW_RELEASE, (unsigned long)pid,
                       request.addr, 0, 0);
            response.status = pr < 0 ? -(int)errno : 0;
            response.value = pr;
        } else if (request.command == GREEN_BROKER_COUNT) {
            pr = prctl((int)PR_GREEN_SHADOW_COUNT, (unsigned long)pid, 0, 0, 0);
            response.status = pr < 0 ? -(int)errno : 0;
            response.value = pr;
        } else {
            response.status = -EOPNOTSUPP;
        }
        if (write(fd, &response, sizeof(response)) != (ssize_t)sizeof(response))
            break;
    }
    close(fd);
    printf("broker channel closed\n");
    return 0;
}

static int agent_request(pid_t pid, uint16_t tool, uint16_t command,
                         uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    struct sockaddr_un address;
    struct green_agent_request request;
    struct green_agent_response response;
    char name[sizeof(address.sun_path) - 1];
    int fd;
    int name_len;

    name_len = green_agent_socket_name(pid, name, sizeof(name));
    if (name_len < 0)
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, (size_t)name_len);
    if (connect(fd, (struct sockaddr *)&address,
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len)) != 0) {
        perror("connect green agent");
        close(fd);
        return -1;
    }

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = tool;
    request.command = command;
    request.size = sizeof(request);
    request.arg0 = arg0;
    request.arg1 = arg1;
    request.arg2 = arg2;
    if (write(fd, &request, sizeof(request)) != (ssize_t)sizeof(request) ||
        read(fd, &response, sizeof(response)) != (ssize_t)sizeof(response)) {
        close(fd);
        return -1;
    }
    close(fd);
    printf("status=%d value=0x%" PRIx64 " %s\n", response.status,
           response.value, response.message);
    return response.status == 0 ? 0 : 1;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  %s inject --pid PID --so /path/in/target/libgreen_agent.so\n"
            "  %s ping --pid PID\n"
            "  %s self-test --pid PID\n"
            "  %s broker --pid PID\n"
            "  %s hook --pid PID --target ADDR --replacement ADDR [--len N]\n"
            "  %s release --pid PID --target ADDR\n", program, program,
            program, program, program, program);
}

static int parse_ulong(const char *text, uintptr_t *value)
{
    char *end;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno || !end || *end || parsed == 0)
        return -1;
    *value = (uintptr_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    const char *command;
    const char *so = NULL;
    uintptr_t pid_value = 0;
    uintptr_t target = 0;
    uintptr_t replacement = 0;
    uintptr_t length = 16;
    int i;

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    command = argv[1];
    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            parse_ulong(argv[++i], &pid_value);
        else if (!strcmp(argv[i], "--so") && i + 1 < argc)
            so = argv[++i];
        else if (!strcmp(argv[i], "--target") && i + 1 < argc)
            parse_ulong(argv[++i], &target);
        else if (!strcmp(argv[i], "--replacement") && i + 1 < argc)
            parse_ulong(argv[++i], &replacement);
        else if (!strcmp(argv[i], "--len") && i + 1 < argc)
            parse_ulong(argv[++i], &length);
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (!pid_value || pid_value > 0x7fffffffU) {
        usage(argv[0]);
        return 2;
    }

    if (!strcmp(command, "inject")) {
        char socket_name[64];

        if (!so || inject_payload((pid_t)pid_value, so) != 0)
            return 1;
        if (green_agent_socket_name((pid_t)pid_value, socket_name,
                                    sizeof(socket_name)) < 0)
            return 1;
        printf("injected; socket=@%s\n", socket_name);
        return 0;
    }
    if (!strcmp(command, "ping"))
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_CORE,
                             GREEN_AGENT_CMD_PING, 0, 0, 0);
    if (!strcmp(command, "broker"))
        return broker_serve((pid_t)pid_value);
    if (!strcmp(command, "self-test"))
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_SELF_TEST, 0, 0, 0);
    if (!strcmp(command, "hook")) {
        if (!target || !replacement || length < 16 || length > 4096)
            return 2;
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_REDIRECT, target, replacement,
                             length);
    }
    if (!strcmp(command, "release")) {
        if (!target)
            return 2;
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_RELEASE, target, 0, 0);
    }
    usage(argv[0]);
    return 2;
}
