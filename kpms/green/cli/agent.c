/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * `green agent` CLI tool: injector, broker and agent client.
 *
 * - inject:  ptrace + remote dlopen of the agent payload into the target.
 * - broker:  attach to the agent as root and serve its privileged
 *            page-table requests (snapshot + GumArm64Writer + prctl).
 * - ping/self-test/hook/release: protocol requests to the agent.
 */

#include <green/cli.h>
#include <green/abi.h>
#include <green_agent.h>

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gum/arch-arm64/gumarm64writer.h>
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

    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS,
               &iov) != 0) {
        perror("PTRACE_GETREGSET");
        return -1;
    }
    return 0;
}

static int set_regs(pid_t pid, const struct user_pt_regs *regs)
{
    struct iovec iov = { .iov_base = (void *)regs, .iov_len = sizeof(*regs) };

    if (ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS,
               &iov) != 0) {
        perror("PTRACE_SETREGSET");
        return -1;
    }
    return 0;
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
    void *local_dlopen;
    uintptr_t remote_dlopen;
    uintptr_t remote_path;
    size_t payload_len = strlen(payload) + 1;
    int status;
    int result = -1;

    local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    fprintf(stderr, "inject: local dlopen=%p\n", local_dlopen);
    if (!local_dlopen) {
        return -1;
    }
    if (find_map_containing(getpid(), (uintptr_t)local_dlopen, &local_map) != 0) {
        fprintf(stderr, "inject: local dlopen map not found\n");
        return -1;
    }
    if (find_target_library_map(pid, &local_map, &target_map) != 0) {
        fprintf(stderr, "inject: target map for %s not found\n",
                local_map.path[0] ? local_map.path : "(anon)");
        return -1;
    }

    remote_dlopen = target_map.start +
        ((uintptr_t)local_dlopen - local_map.start);

    /* Park sp well BELOW the thread's live frames: the hijacked call grows
     * its stack downward through unused territory only.  (Using the top of
     * the stack mapping made dlopen overwrite live frames and trip the
     * stack-protector once the thread resumed.) */
    if (get_regs(pid, &saved) != 0)
        return -1;
    remote_path = (saved.sp - 0x8000) & ~(uintptr_t)0xf;
    if (remote_write(pid, remote_path, payload, payload_len) != 0) {
        perror("write remote payload path");
        return -1;
    }
    if (get_regs(pid, &saved) != 0)
        return -1;
    fprintf(stderr, "inject: calling target dlopen at %lx (path @%lx)\n",
            (unsigned long)remote_dlopen, (unsigned long)remote_path);
    call = saved;
    call.regs[0] = remote_path;
    call.regs[1] = RTLD_NOW | RTLD_GLOBAL;
    call.sp = remote_path & ~(uintptr_t)0xf;
    call.regs[30] = 0; /* return to address 0; ptrace catches SIGSEGV */
    call.pc = remote_dlopen;
    if (set_regs(pid, &call) != 0)
        return -1;

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        perror("PTRACE_CONT");
        goto restore;
    }
    for (;;) {
        if (waitpid(pid, &status, __WALL) != pid) {
            perror("waitpid(dlopen)");
            goto restore;
        }
        if (!WIFSTOPPED(status))
            goto restore;
        if (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGBUS) {
            struct user_pt_regs after;
            if (get_regs(pid, &after) == 0 && after.pc == 0) {
                if (after.regs[0] != 0) {
                    result = 0;
                    fprintf(stderr, "inject: remote dlopen handle=%llx\n",
                            (unsigned long long)after.regs[0]);
                } else {
                    /* dlopen failed: pull dlerror() text from the target. */
                    struct user_pt_regs call = after;
                    void *local_dlerror = dlsym(RTLD_DEFAULT, "dlerror");
                    struct map_entry lmap, tmap;

                    fprintf(stderr, "inject: remote dlopen returned NULL\n");
                    if (local_dlerror &&
                        find_map_containing(getpid(),
                                            (uintptr_t)local_dlerror,
                                            &lmap) == 0 &&
                        find_target_library_map(pid, &lmap, &tmap) == 0) {
                        call = after;
                        call.pc = tmap.start +
                            ((uintptr_t)local_dlerror - lmap.start);
                        call.regs[30] = 0;
                        call.sp = after.sp;
                        if (set_regs(pid, &call) == 0) {
                            int st2;
                            ptrace(PTRACE_CONT, pid, NULL, NULL);
                            while (waitpid(pid, &st2, __WALL) == pid &&
                                   WIFSTOPPED(st2)) {
                                struct user_pt_regs r2;
                                if (WSTOPSIG(st2) == SIGSEGV &&
                                    get_regs(pid, &r2) == 0 && r2.pc == 0) {
                                    char err[256] = {0};
                                    struct iovec lo = {
                                        .iov_base = err,
                                        .iov_len = sizeof(err) - 1 };
                                    struct iovec ro = {
                                        .iov_base = (void *)r2.regs[0],
                                        .iov_len = sizeof(err) - 1 };
                                    process_vm_readv(pid, &lo, 1, &ro, 1, 0);
                                    fprintf(stderr, "inject: dlerror: %s\n",
                                            err);
                                    break;
                                }
                                ptrace(PTRACE_CONT, pid, NULL,
                                       (void *)(uintptr_t)WSTOPSIG(st2));
                            }
                        }
                    }
                    result = -1;
                }
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

    fprintf(stderr, "inject: attaching to %d\n", (int)pid);
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
static int connect_agent(pid_t pid)
{
    struct sockaddr_un address;
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
        fprintf(stderr, "connect agent: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* Snapshot the target page cross-process, emit the redirect with the real
 * GumArm64Writer, and commit it through the shadow ABI. */
static int read_full(int fd, void *buf, size_t size)
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

static int write_full(int fd, const void *buf, size_t size)
{
    size_t done = 0;

    while (done < size) {
        ssize_t n = write(fd, (const char *)buf + done, size - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

static int broker_patch(pid_t target, unsigned long target_addr,
                        unsigned long replacement, long *out_value)
{
    unsigned long page = target_addr & ~4095UL;
    size_t offset = (size_t)(target_addr - page);
    static guint8 snapshot[4096];
    struct iovec local = { .iov_base = snapshot, .iov_len = sizeof(snapshot) };
    struct iovec remote = { .iov_base = (void *)page,
                            .iov_len = sizeof(snapshot) };
    GumArm64Writer writer;
    ssize_t n;
    long pr;

    if ((target_addr & 3) || (replacement & 3) || offset > 4096 - 16)
        return -EINVAL;

    do {
        n = process_vm_readv((pid_t)target, &local, 1, &remote, 1, 0);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(snapshot)) {
        fprintf(stderr, "broker: process_vm_readv failed: %s\n", strerror(errno));
        return -EIO;
    }

    gum_arm64_writer_init(&writer, snapshot + offset);
    writer.pc = (GumAddress)target_addr;
    gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16,
                                         (guint64)replacement);
    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);

    pr = green_cli_prctl(PR_GREEN_SHADOW_PATCH, target, page,
                         (unsigned long)snapshot, sizeof(snapshot));
    *out_value = pr;
    return pr < 0 ? (int)pr : 0;
}

/* One command = one pair of connections:
 *   conn A: the command request and its final agent response;
 *   conn B: attached as the broker; the agent forwards its privileged
 *           page-table requests here while the command runs. */
static int agent_request(pid_t pid, uint16_t tool, uint16_t command,
                         uint64_t arg0, uint64_t arg1, uint64_t arg2);

/* Deploy the user script to the path used by the target-side runtime, load
 * it, then call the probe so the registered hook is exercised. */
static int agent_js_load(pid_t pid, const char *script_path)
{
    char proc_path[64];
    char cmdline[128] = {0};
    char package[128];
    char dest[300];
    char buf[8192];
    const char *slash;
    const char *colon;
    struct stat process_stat;
    struct stat source_stat;
    struct stat dest_stat;
    ssize_t n;
    int src;
    int dst;
    int r;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
    if (stat(proc_path, &process_stat) != 0) {
        fprintf(stderr, "js: target %d is not running: %s\n", (int)pid,
                strerror(errno));
        return 1;
    }

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", (int)pid);
    src = open(proc_path, O_RDONLY);
    if (src < 0) {
        fprintf(stderr, "js: open %s: %s\n", proc_path, strerror(errno));
        return 1;
    }
    n = read(src, cmdline, sizeof(cmdline) - 1);
    close(src);
    if (n <= 0) {
        fprintf(stderr, "js: read %s: %s\n", proc_path,
                n < 0 ? strerror(errno) : "empty cmdline");
        return 1;
    }
    cmdline[n] = '\0';

    slash = strrchr(cmdline, '/');
    if (slash) {
        /* Non-app target: deploy next to its executable. */
        size_t dir_len = (size_t)(slash - cmdline) + 1;
        snprintf(dest, sizeof(dest), "%.*sgreen_hook.js", (int)dir_len,
                 cmdline);
    } else {
        /* App services use "package:process" as cmdline; their data
         * directory is still named after the base package. */
        colon = strchr(cmdline, ':');
        snprintf(package, sizeof(package), "%.*s",
                 colon ? (int)(colon - cmdline) : (int)strlen(cmdline),
                 cmdline);
        snprintf(dest, sizeof(dest), "/data/user/0/%s/cache/green_hook.js",
                 package);
    }

    fprintf(stderr, "js: script %s -> %s\n", script_path, dest);
    if (strcmp(script_path, dest) != 0) {
        src = open(script_path, O_RDONLY);
        if (src < 0) {
            fprintf(stderr, "js: open %s: %s\n", script_path,
                    strerror(errno));
            return 1;
        }
        if (fstat(src, &source_stat) != 0) {
            perror("js: fstat script");
            close(src);
            return 1;
        }

        /* Different path strings can still name the same inode.  Never open
         * the destination with O_TRUNC in that case. */
        if (stat(dest, &dest_stat) == 0 &&
            source_stat.st_dev == dest_stat.st_dev &&
            source_stat.st_ino == dest_stat.st_ino) {
            close(src);
        } else {
            dst = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (dst < 0) {
                fprintf(stderr, "js: open %s: %s\n", dest, strerror(errno));
                close(src);
                return 1;
            }
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                if (write_full(dst, buf, (size_t)n) != 0) {
                    perror("js: write script");
                    close(src);
                    close(dst);
                    return 1;
                }
            }
            close(src);
            if (n < 0 || fchmod(dst, 0644) != 0 ||
                fchown(dst, process_stat.st_uid, process_stat.st_gid) != 0) {
                perror("js: finalize script");
                close(dst);
                return 1;
            }
            close(dst);
        }
    }

    /* Each request owns a broker connection until its response arrives.
     * The JS state and committed shadow page persist between requests. */
    r = agent_request(pid, GREEN_AGENT_TOOL_JS, GREEN_AGENT_CMD_JS_LOAD,
                      0, 0, 0);
    if (r != 0)
        return r;
    return agent_request(pid, GREEN_AGENT_TOOL_JS, GREEN_AGENT_CMD_JS_CALL,
                         0, 0, 0);
}

static int agent_request(pid_t pid, uint16_t tool, uint16_t command,
                         uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    struct green_agent_request request;
    struct green_agent_response response;
    int cmd_fd;
    int broker_fd;
    int status = 1;

    /* conn A: the command; conn B: attached as the broker so the agent can
     * forward its privileged page-table requests while the command runs. */
    cmd_fd = connect_agent(pid);
    if (cmd_fd < 0)
        return 1;
    broker_fd = connect_agent(pid);
    if (broker_fd < 0) {
        close(cmd_fd);
        return 1;
    }

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = GREEN_AGENT_TOOL_CORE;
    request.command = GREEN_AGENT_CMD_BROKER_ATTACH;
    request.size = sizeof(request);
    if (write_full(broker_fd, &request, sizeof(request)) != 0) {
        close(broker_fd);
        close(cmd_fd);
        return 1;
    }
    if (read_full(broker_fd, &response, sizeof(response)) != 0 ||
        response.status != 0) {
        fprintf(stderr, "broker attach failed\n");
        close(broker_fd);
        close(cmd_fd);
        return 1;
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
    if (write_full(cmd_fd, &request, sizeof(request)) != 0) {
        close(cmd_fd);
        close(broker_fd);
        return 1;
    }

    for (;;) {
        struct pollfd fds[2] = {
            { .fd = broker_fd, .events = POLLIN },
            { .fd = cmd_fd, .events = POLLIN },
        };
        struct green_broker_request breq;
        struct green_broker_response bresp;
        long pr = 0;

        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (fds[0].revents & POLLIN) {
            memset(&bresp, 0, sizeof(bresp));
            if (read_full(broker_fd, &breq, sizeof(breq)) != 0)
                break;
            memset(&bresp, 0, sizeof(bresp));
            if (breq.magic != GREEN_AGENT_MAGIC)
                bresp.status = -EBADMSG;
            else if (breq.command == GREEN_BROKER_PATCH && breq.len > 0) {
                /* payload-side gum commit: image follows the header */
                unsigned char img[4096];
                long pr;

                if (breq.len > 4096 ||
                    read_full(broker_fd, img, breq.len) != 0) {
                    bresp.status = -EBADMSG;
                } else {
                    pr = green_cli_prctl(PR_GREEN_SHADOW_PATCH, pid,
                                         breq.addr, (unsigned long)img,
                                         breq.len);
                    bresp.status = pr < 0 ? (int32_t)pr : 0;
                    bresp.value = pr;
                }
            } else if (breq.command == GREEN_BROKER_PATCH)
                bresp.status = (int32_t)broker_patch(pid, breq.addr,
                                                     breq.arg, &bresp.value);
            else if (breq.command == GREEN_BROKER_RELEASE) {
                pr = green_cli_prctl(PR_GREEN_SHADOW_RELEASE, pid, breq.addr,
                                     0, 0);
                bresp.status = pr < 0 ? (int32_t)pr : 0;
                bresp.value = pr;
            } else if (breq.command == GREEN_BROKER_COUNT) {
                pr = green_cli_prctl(PR_GREEN_SHADOW_COUNT, pid, 0, 0, 0);
                bresp.status = pr < 0 ? (int32_t)pr : 0;
                bresp.value = pr;
            } else {
                bresp.status = -EOPNOTSUPP;
            }
            if (write_full(broker_fd, &bresp, sizeof(bresp)) != 0)
                break;
        }

        if (fds[1].revents & POLLIN) {
            if (read_full(cmd_fd, &response, sizeof(response)) != 0)
                break;
            printf("status=%d value=0x%" PRIx64 " %s\n", response.status,
                   response.value, response.message);
            status = response.status == 0 ? 0 : 1;
            break;
        }
    }

    close(cmd_fd);
    close(broker_fd);
    return status;
}

static void agent_usage(const char *prog)
{
    fprintf(stderr,
            "Green agent tool (injector, broker, client)\n\n"
            "Usage:\n"
            "  %s agent inject --pid PID --so /path/in/target/libgreen_agent.so\n"
            "  %s agent ping --pid PID\n"
            "  %s agent js --pid PID --file /path/to/script.js\n"
            "  %s agent self-test --pid PID\n"
            "  %s agent hook --pid PID --target ADDR --replacement ADDR\n"
            "  %s agent release --pid PID --target ADDR\n",
            prog, prog, prog, prog, prog, prog);
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

int green_agent_main(int argc, char **argv)
{
    const char *command;
    const char *so = NULL;
    const char *script_file = NULL;
    unsigned long pid_value = 0;
    uintptr_t target = 0;
    uintptr_t replacement = 0;
    int i;

    if (argc < 2) {
        agent_usage("green");
        return argc < 2 ? 1 : 0;
    }
    command = argv[1];
    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            green_cli_parse_pid(argv[++i], (pid_t *)&pid_value);
        else if (!strcmp(argv[i], "--so") && i + 1 < argc)
            so = argv[++i];
        else if (!strcmp(argv[i], "--target") && i + 1 < argc)
            parse_ulong(argv[++i], &target);
        else if (!strcmp(argv[i], "--replacement") && i + 1 < argc)
            parse_ulong(argv[++i], &replacement);
        else if (!strcmp(argv[i], "--file") && i + 1 < argc)
            script_file = argv[++i];
        else {
            agent_usage("green");
            return 2;
        }
    }
    if (!pid_value || pid_value > 0x7fffffffUL) {
        agent_usage("green");
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
    if (!strcmp(command, "js")) {
        if (!script_file) { fprintf(stderr, "js: --file required (device path of the script)\n"); return 2; }
        return agent_js_load((pid_t)pid_value, script_file);
    }
    if (!strcmp(command, "self-test"))
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_SELF_TEST, 0, 0, 0);
    if (!strcmp(command, "hook")) {
        if (!target || !replacement)
            return 2;
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_REDIRECT, target, replacement,
                             16);
    }
    if (!strcmp(command, "release")) {
        if (!target)
            return 2;
        return agent_request((pid_t)pid_value, GREEN_AGENT_TOOL_GREEN_HOOK,
                             GREEN_AGENT_HOOK_RELEASE, target, 0, 0);
    }
    agent_usage("green");
    return 2;
}

const struct green_cli_tool green_cli_agent_tool = {
    .name = "agent",
    .summary = "inject/serve/hook through the in-process green agent",
    .main = green_agent_main,
    .usage = agent_usage,
};
