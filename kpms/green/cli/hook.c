/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * `green hook` CLI: attach to a target process and run a QuickJS hook
 * script through the in-process agent payload (libgreen_agent.so).
 *
 * - attach: resolve the target (-p pid / -f package), inject the payload if
 *   the agent socket is not up yet, deploy the script (-l file or -c inline
 *   code) to the target's script path and evaluate it.  Each request
 *   attaches its own root broker connection; the agent forwards its
 *   privileged page-table requests (snapshot + GumArm64Writer + prctl)
 *   over that connection.
 * - spawn:  reserved (not implemented yet).
 */

#include <green/cli.h>
#include <green/abi.h>
#include <green_agent.h>

#include <dirent.h>
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
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/un.h>
#include <stddef.h>
#include <unistd.h>

#include <gum/arch-arm64/gumarm64writer.h>

/* Well-known device paths; push both there before attaching. */
#define HOOK_SO_SOURCE "/data/local/tmp/libgreen_agent.so"
#define HOOK_SCRIPT_NAME "green_hook.js"

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
    if (!local_dlopen)
        return -1;
    if (find_map_containing(getpid(), (uintptr_t)local_dlopen, &local_map) != 0) {
        fprintf(stderr, "hook: local dlopen map not found\n");
        return -1;
    }
    if (find_target_library_map(pid, &local_map, &target_map) != 0) {
        fprintf(stderr, "hook: target map for %s not found\n",
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
                    fprintf(stderr, "hook: injected %s (handle=%llx)\n",
                            payload, (unsigned long long)after.regs[0]);
                } else {
                    /* dlopen failed: pull dlerror() text from the target. */
                    struct user_pt_regs call = after;
                    void *local_dlerror = dlsym(RTLD_DEFAULT, "dlerror");
                    struct map_entry lmap, tmap;

                    fprintf(stderr, "hook: remote dlopen returned NULL\n");
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
                                    fprintf(stderr, "hook: dlerror: %s\n",
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
    int result;

    fprintf(stderr, "hook: attaching to %d\n", (int)pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        return -1;
    }
    if (wait_initial_stop(pid) != 0) {
        fprintf(stderr, "hook: target did not stop\n");
        result = -1;
        goto detach;
    }
    result = remote_dlopen(pid, payload) == 0 ? 0 : -1;

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return result;
}

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
        close(fd);
        return -1;
    }
    return fd;
}

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

/* Snapshot the target page cross-process, emit the redirect with the real
 * GumArm64Writer, and commit it through the shadow ABI. */
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
        fprintf(stderr, "hook: process_vm_readv failed: %s\n",
                strerror(errno));
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

/* One request = one pair of connections:
 *   conn A: the command request and its final agent response;
 *   conn B: attached as the broker; the agent forwards its privileged
 *           page-table requests here while the command runs. */
static int hook_request(pid_t pid, uint16_t tool, uint16_t command,
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
        fprintf(stderr, "hook: broker attach failed\n");
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

/* Silent liveness probe (PING needs no broker channel). */
static int agent_alive(pid_t pid)
{
    struct green_agent_request request;
    struct green_agent_response response;
    int cmd_fd;
    int ok;

    cmd_fd = connect_agent(pid);
    if (cmd_fd < 0)
        return 0;
    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = GREEN_AGENT_TOOL_CORE;
    request.command = GREEN_AGENT_CMD_PING;
    request.size = sizeof(request);
    ok = write_full(cmd_fd, &request, sizeof(request)) == 0 &&
         read_full(cmd_fd, &response, sizeof(response)) == 0 &&
         response.status == 0;
    close(cmd_fd);
    return ok;
}

static int read_cmdline(pid_t pid, char *out, size_t out_size)
{
    char path[64];
    ssize_t n;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    n = read(fd, out, out_size - 1);
    close(fd);
    if (n <= 0)
        return -1;
    out[n] = '\0';
    return 0;
}

/* App services use "package:process" as cmdline but share the base
 * package's data directory. */
static void base_package(const char *cmdline, char *out, size_t out_size)
{
    const char *colon = strchr(cmdline, ':');

    snprintf(out, out_size, "%.*s",
             colon ? (int)(colon - cmdline) : (int)strlen(cmdline), cmdline);
}

static void target_file_path(const char *cmdline, const char *file,
                             char *out, size_t out_size)
{
    const char *slash = strrchr(cmdline, '/');
    char package[128];

    if (slash) {
        /* Non-app target: deploy next to its executable. */
        size_t dir_len = (size_t)(slash - cmdline) + 1;
        snprintf(out, out_size, "%.*s%s", (int)dir_len, cmdline, file);
    } else {
        base_package(cmdline, package, sizeof(package));
        snprintf(out, out_size, "/data/user/0/%s/cache/%s", package, file);
    }
}

static void chown_to_target(int fd, pid_t pid)
{
    char path[64];
    struct stat st;

    snprintf(path, sizeof(path), "/proc/%d", (int)pid);
    if (stat(path, &st) == 0)
        fchown(fd, st.st_uid, st.st_gid);
}

static pid_t find_pid_by_package(const char *package)
{
    DIR *dir;
    struct dirent *de;
    pid_t found = 0;
    size_t pkg_len = strlen(package);

    dir = opendir("/proc");
    if (!dir)
        return 0;
    while ((de = readdir(dir)) != NULL) {
        char cmdline[128];
        pid_t pid;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = (pid_t)atoi(de->d_name);
        if (pid <= 0 || read_cmdline(pid, cmdline, sizeof(cmdline)) != 0)
            continue;
        if (strcmp(cmdline, package) == 0) {
            /* Exact match wins over a ":process" suffix match. */
            closedir(dir);
            return pid;
        }
        if (!found && strlen(cmdline) > pkg_len &&
            strncmp(cmdline, package, pkg_len) == 0 &&
            cmdline[pkg_len] == ':')
            found = pid;
    }
    closedir(dir);
    return found;
}

static int hook_attach(pid_t pid, const char *script_file,
                       const char *inline_code)
{
    char cmdline[128];
    char proc_path[64];
    char dest[300];
    char buf[8192];
    struct stat pst;
    ssize_t n;
    int sfd;
    int dfd;
    int r;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
    if (stat(proc_path, &pst) != 0) {
        fprintf(stderr, "hook: target %d is not running: %s\n", (int)pid,
                strerror(errno));
        return 1;
    }
    if (read_cmdline(pid, cmdline, sizeof(cmdline)) != 0) {
        fprintf(stderr, "hook: cannot read cmdline of %d\n", (int)pid);
        return 1;
    }

    /* Inject the payload unless the agent socket is already serving. */
    if (!agent_alive(pid)) {
        char so_path[300];
        int i;

        if (access(HOOK_SO_SOURCE, R_OK) != 0) {
            fprintf(stderr,
                    "hook: %s not found; push libgreen_agent.so there first\n",
                    HOOK_SO_SOURCE);
            return 1;
        }
        if (!strchr(cmdline, '/')) {
            /* App target: the payload must live inside its own data dir. */
            target_file_path(cmdline, "libgreen_agent.so", so_path,
                             sizeof(so_path));
            sfd = open(HOOK_SO_SOURCE, O_RDONLY);
            if (sfd < 0) {
                fprintf(stderr, "hook: open %s: %s\n", HOOK_SO_SOURCE,
                        strerror(errno));
                return 1;
            }
            dfd = open(so_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (dfd < 0) {
                fprintf(stderr, "hook: open %s: %s\n", so_path,
                        strerror(errno));
                close(sfd);
                return 1;
            }
            while ((n = read(sfd, buf, sizeof(buf))) > 0) {
                if (write_full(dfd, buf, (size_t)n) != 0) {
                    perror("hook: write payload");
                    close(sfd);
                    close(dfd);
                    return 1;
                }
            }
            close(sfd);
            fchmod(dfd, 0755);
            chown_to_target(dfd, pid);
            close(dfd);
        } else {
            snprintf(so_path, sizeof(so_path), "%s", HOOK_SO_SOURCE);
        }

        if (inject_payload(pid, so_path) != 0) {
            fprintf(stderr, "hook: injection failed\n");
            return 1;
        }
        for (i = 0; i < 25 && !agent_alive(pid); i++)
            usleep(200 * 1000);
        if (!agent_alive(pid)) {
            fprintf(stderr, "hook: agent socket did not come up\n");
            return 1;
        }
    }

    /* Deploy the script where the payload's JS runtime will read it. */
    target_file_path(cmdline, HOOK_SCRIPT_NAME, dest, sizeof(dest));
    fprintf(stderr, "hook: script -> %s\n", dest);
    dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        fprintf(stderr, "hook: open %s: %s\n", dest, strerror(errno));
        return 1;
    }
    if (inline_code) {
        if (write_full(dfd, inline_code, strlen(inline_code)) != 0 ||
            write_full(dfd, "\n", 1) != 0) {
            perror("hook: write script");
            close(dfd);
            return 1;
        }
    } else {
        sfd = open(script_file, O_RDONLY);
        if (sfd < 0) {
            fprintf(stderr, "hook: open %s: %s\n", script_file,
                    strerror(errno));
            close(dfd);
            return 1;
        }
        while ((n = read(sfd, buf, sizeof(buf))) > 0) {
            if (write_full(dfd, buf, (size_t)n) != 0) {
                perror("hook: write script");
                close(sfd);
                close(dfd);
                return 1;
            }
        }
        close(sfd);
        if (n < 0) {
            perror("hook: read script");
            close(dfd);
            return 1;
        }
    }
    fchmod(dfd, 0644);
    chown_to_target(dfd, pid);
    close(dfd);

    r = hook_request(pid, GREEN_AGENT_TOOL_JS, GREEN_AGENT_CMD_JS_LOAD,
                     0, 0, 0);
    if (r != 0)
        return r;
    return 0;
}

static void hook_usage(const char *prog)
{
    fprintf(stderr,
            "Green hook: attach a target and run a QuickJS hook script\n\n"
            "Usage:\n"
            "  %s attach -f <package> -l <script.js>\n"
            "  %s attach -p <pid> -l <script.js>\n"
            "  %s attach -p <pid> -c \"<js code>\"\n"
            "  %s spawn <package>          (not implemented yet)\n\n"
            "Options:\n"
            "  -f <package>   target Android package (running process)\n"
            "  -p <pid>       target pid\n"
            "  -l <script.js> hook script file (device path)\n"
            "  -c \"<js code>\"  inline hook script\n\n"
            "Push the payload first: adb push libgreen_agent.so %s\n",
            prog, prog, prog, prog, HOOK_SO_SOURCE);
}

int green_hook_main(int argc, char **argv)
{
    const char *command;
    const char *package = NULL;
    const char *script_file = NULL;
    const char *inline_code = NULL;
    unsigned long pid_value = 0;
    int i;

    if (argc < 2) {
        hook_usage(argv[0]);
        return 1;
    }
    command = argv[1];

    if (!strcmp(command, "spawn")) {
        if (argc < 3) {
            hook_usage(argv[0]);
            return 2;
        }
        fprintf(stderr, "hook: spawn %s is not implemented yet\n", argv[2]);
        return 2;
    }

    if (strcmp(command, "attach") != 0) {
        hook_usage(argv[0]);
        return 2;
    }

    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc)
            package = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc)
            green_cli_parse_pid(argv[++i], (pid_t *)&pid_value);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc)
            script_file = argv[++i];
        else if (!strcmp(argv[i], "-c") && i + 1 < argc)
            inline_code = argv[++i];
        else {
            hook_usage(argv[0]);
            return 2;
        }
    }

    if ((pid_value == 0) == (package == NULL)) {
        fprintf(stderr, "hook: attach needs exactly one of -f/-p\n");
        return 2;
    }
    if ((script_file == NULL) == (inline_code == NULL)) {
        fprintf(stderr, "hook: attach needs exactly one of -l/-c\n");
        return 2;
    }
    if (package) {
        pid_t pid = find_pid_by_package(package);

        if (pid <= 0) {
            fprintf(stderr, "hook: no running process for %s\n", package);
            return 1;
        }
        pid_value = (unsigned long)pid;
        fprintf(stderr, "hook: %s -> pid %ld\n", package,
                (long)pid_value);
    }

    return hook_attach((pid_t)pid_value, script_file, inline_code);
}

const struct green_cli_tool green_cli_hook_tool = {
    .name = "hook",
    .summary = "attach a target and run a QuickJS hook script",
    .main = green_hook_main,
    .usage = hook_usage,
};
