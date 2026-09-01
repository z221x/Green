/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared agent-driving primitives: ptrace injector, protocol client and
 * broker plumbing used by `green hook` and `green server`.
 */

#include <green/agentops.h>
#include <green/abi.h>
#include <green/cli.h>
#include <green_agent.h>

#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <linux/ptrace.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <poll.h>
#include <linux/un.h>
#include <stddef.h>
#include <unistd.h>

#include <gum/arch-arm64/gumarm64writer.h>

int green_agentops_read_full(int fd, void *buf, size_t size)
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

int green_agentops_write_full(int fd, const void *buf, size_t size)
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

int green_agentops_connect(pid_t pid)
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
                (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                            name_len)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int green_agentops_ping_ok(pid_t pid)
{
    struct green_agent_request request;
    struct green_agent_response response;
    int fd;
    int ok;

    fd = green_agentops_connect(pid);
    if (fd < 0)
        return 0;
    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = GREEN_AGENT_TOOL_CORE;
    request.command = GREEN_AGENT_CMD_PING;
    request.size = sizeof(request);
    ok = green_agentops_write_full(fd, &request, sizeof(request)) == 0 &&
         green_agentops_read_full(fd, &response, sizeof(response)) == 0 &&
         response.status == 0;
    close(fd);
    return ok;
}

int green_agentops_broker_attach(pid_t pid, int broker_fd)
{
    struct green_agent_request request;
    struct green_agent_response response;

    (void)pid;

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = GREEN_AGENT_TOOL_CORE;
    request.command = GREEN_AGENT_CMD_BROKER_ATTACH;
    request.size = sizeof(request);
    if (green_agentops_write_full(broker_fd, &request, sizeof(request)) != 0)
        return -1;
    if (green_agentops_read_full(broker_fd, &response, sizeof(response)) != 0 ||
        response.status != 0) {
        fprintf(stderr, "hook: broker attach failed\n");
        return -1;
    }
    return 0;
}

int green_agentops_send_request(int fd, uint16_t tool, uint16_t command,
                                uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    struct green_agent_request request;

    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.version = GREEN_AGENT_VERSION;
    request.tool = tool;
    request.command = command;
    request.size = sizeof(request);
    request.arg0 = arg0;
    request.arg1 = arg1;
    request.arg2 = arg2;
    return green_agentops_write_full(fd, &request, sizeof(request));
}

int green_agentops_read_response(int fd, struct green_agent_response *out)
{
    return green_agentops_read_full(fd, out, sizeof(*out));
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

int green_agentops_broker_serve_one(pid_t pid, int broker_fd,
                                    green_agentops_log_cb logcb, void *ud)
{
    struct green_broker_request breq;
    struct green_broker_response bresp;
    long pr = 0;
    int32_t status;

    if (green_agentops_read_full(broker_fd, &breq, sizeof(breq)) != 0)
        return 1; /* clean EOF: the agent closed or replaced the channel */

    memset(&bresp, 0, sizeof(bresp));
    status = 0;
    if (breq.magic != GREEN_AGENT_MAGIC) {
        status = -EBADMSG;
    } else if (breq.command == GREEN_BROKER_LOG) {
        /* one-way script log; not answered */
        static char text[8192];
        uint32_t len = breq.len;

        if (len > sizeof(text))
            len = sizeof(text);
        if (len > 0 &&
            green_agentops_read_full(broker_fd, text, len) != 0)
            return -1;
        if (logcb)
            logcb((int32_t)pid, text, len, ud);
        return 0;
    } else if (breq.command == GREEN_BROKER_PATCH && breq.len > 0) {
        /* payload-side gum commit: image follows the header */
        unsigned char img[4096];

        if (breq.len > 4096 ||
            green_agentops_read_full(broker_fd, img, breq.len) != 0) {
            status = -EBADMSG;
        } else {
            pr = green_cli_prctl(PR_GREEN_SHADOW_PATCH, pid, breq.addr,
                                 (unsigned long)img, breq.len);
            bresp.status = pr < 0 ? (int32_t)pr : 0;
            bresp.value = pr;
        }
    } else if (breq.command == GREEN_BROKER_PATCH) {
        status = broker_patch(pid, breq.addr, breq.arg, &bresp.value);
        bresp.status = (int32_t)status;
    } else if (breq.command == GREEN_BROKER_RELEASE) {
        pr = green_cli_prctl(PR_GREEN_SHADOW_RELEASE, pid, breq.addr, 0, 0);
        bresp.status = pr < 0 ? (int32_t)pr : 0;
        bresp.value = pr;
    } else if (breq.command == GREEN_BROKER_COUNT) {
        pr = green_cli_prctl(PR_GREEN_SHADOW_COUNT, pid, 0, 0, 0);
        bresp.status = pr < 0 ? (int32_t)pr : 0;
        bresp.value = pr;
    } else {
        status = -EOPNOTSUPP;
    }
    if (status != 0 && bresp.status == 0)
        bresp.status = status;
    if (green_agentops_write_full(broker_fd, &bresp, sizeof(bresp)) != 0)
        return -1;
    return 0;
}

struct map_entry {
    uintptr_t start;
    uintptr_t end;
    unsigned long offset;
    char perms[5];
    char path[512];
};

static int find_map_containing(pid_t pid, uintptr_t address,
                               struct map_entry *out);
static int find_target_library_map(pid_t pid, const struct map_entry *local,
                                   struct map_entry *target);

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
    if (find_map_containing(getpid(), (uintptr_t)local_dlopen, &local_map) !=
        0) {
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
     * its stack downward through unused territory only. */
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
                            payload,
                            (unsigned long long)after.regs[0]);
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
        if (ptrace(PTRACE_CONT, pid, NULL,
                   (void *)(uintptr_t)WSTOPSIG(status)) != 0)
            break;
    }

restore:
    if (set_regs(pid, &saved) != 0)
        result = -1;
    return result;
}

int green_agentops_inject(pid_t pid, const char *so_path)
{
    fprintf(stderr, "hook: attaching to %d\n", (int)pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        return -1;
    }
    if (wait_initial_stop(pid) != 0) {
        fprintf(stderr, "hook: target did not stop\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }
    if (remote_dlopen(pid, so_path) == 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return -1;
}

int green_agentops_read_cmdline(pid_t pid, char *out, size_t out_size)
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

pid_t green_agentops_find_package(const char *package)
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
        if (pid <= 0 ||
            green_agentops_read_cmdline(pid, cmdline, sizeof(cmdline)) != 0)
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

/* App services use "package:process" as cmdline but share the base
 * package's data directory. */
static void base_package(const char *cmdline, char *out, size_t out_size)
{
    const char *colon = strchr(cmdline, ':');

    snprintf(out, out_size, "%.*s",
             colon ? (int)(colon - cmdline) : (int)strlen(cmdline), cmdline);
}

void green_agentops_target_path(const char *cmdline, const char *file,
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

int green_agentops_copy_file(const char *src, const char *dest, pid_t pid,
                             int executable)
{
    char buf[8192];
    struct stat pst;
    ssize_t n;
    int sfd;
    int dfd;
    mode_t mode = executable ? 0755 : 0644;

    snprintf(buf, sizeof(buf), "/proc/%d", (int)pid);
    if (stat(buf, &pst) != 0)
        return -1;

    sfd = open(src, O_RDONLY);
    if (sfd < 0)
        return -1;
    dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dfd < 0) {
        close(sfd);
        return -1;
    }
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (green_agentops_write_full(dfd, buf, (size_t)n) != 0) {
            close(sfd);
            close(dfd);
            return -1;
        }
    }
    close(sfd);
    if (n < 0 || fchmod(dfd, mode) != 0 ||
        fchown(dfd, pst.st_uid, pst.st_gid) != 0) {
        close(dfd);
        return -1;
    }
    close(dfd);
    return 0;
}

int green_agentops_ensure_injected(pid_t pid, char *err, size_t errlen)
{
    char cmdline[128];
    char so_path[300];

    if (green_agentops_ping_ok(pid))
        return 0;

    if (access(GREEN_AGENT_SO_SOURCE, R_OK) != 0) {
        snprintf(err, errlen, "%s not found; push libgreen_agent.so there",
                 GREEN_AGENT_SO_SOURCE);
        return -1;
    }
    if (green_agentops_read_cmdline(pid, cmdline, sizeof(cmdline)) != 0) {
        snprintf(err, errlen, "cannot read cmdline of %d", (int)pid);
        return -1;
    }
    if (!strchr(cmdline, '/')) {
        /* App target: the payload must live inside its own data dir. */
        green_agentops_target_path(cmdline, "libgreen_agent.so", so_path,
                                   sizeof(so_path));
        if (green_agentops_copy_file(GREEN_AGENT_SO_SOURCE, so_path, pid, 1) !=
            0) {
            snprintf(err, errlen, "cannot deploy payload to %s: %s", so_path,
                     strerror(errno));
            return -1;
        }
    } else {
        snprintf(so_path, sizeof(so_path), "%s", GREEN_AGENT_SO_SOURCE);
    }

    if (green_agentops_inject(pid, so_path) != 0) {
        snprintf(err, errlen, "injection failed");
        return -1;
    }
    for (int i = 0; i < 25 && !green_agentops_ping_ok(pid); i++)
        usleep(200 * 1000);
    if (!green_agentops_ping_ok(pid)) {
        snprintf(err, errlen, "agent socket did not come up");
        return -1;
    }
    return 0;
}

int green_agentops_deploy_script(pid_t pid, const char *script_file,
                                 const char *inline_code, char *dest,
                                 size_t dest_size, char *err, size_t errlen)
{
    char cmdline[128];
    char buf[8192];
    struct stat source_stat;
    struct stat dest_stat;
    ssize_t n;
    int sfd;
    int dfd;

    if (green_agentops_read_cmdline(pid, cmdline, sizeof(cmdline)) != 0) {
        snprintf(err, errlen, "cannot read cmdline of %d", (int)pid);
        return -1;
    }
    green_agentops_target_path(cmdline, GREEN_AGENT_SCRIPT_NAME, dest,
                               dest_size);

    if (inline_code) {
        dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dfd < 0) {
            snprintf(err, errlen, "open %s: %s", dest, strerror(errno));
            return -1;
        }
        if (green_agentops_write_full(dfd, inline_code, strlen(inline_code)) !=
                0 ||
            green_agentops_write_full(dfd, "\n", 1) != 0) {
            snprintf(err, errlen, "write %s: %s", dest, strerror(errno));
            close(dfd);
            return -1;
        }
        fchmod(dfd, 0644);
        {
            char proc_path[64];
            struct stat pst;
            snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
            if (stat(proc_path, &pst) == 0)
                fchown(dfd, pst.st_uid, pst.st_gid);
        }
        close(dfd);
        return 0;
    }

    /* File source: different path strings can still name the same inode;
     * never open the destination with O_TRUNC in that case. */
    sfd = open(script_file, O_RDONLY);
    if (sfd < 0) {
        snprintf(err, errlen, "open %s: %s", script_file, strerror(errno));
        return -1;
    }
    if (fstat(sfd, &source_stat) != 0) {
        snprintf(err, errlen, "stat %s: %s", script_file, strerror(errno));
        close(sfd);
        return -1;
    }
    if (stat(dest, &dest_stat) == 0 &&
        source_stat.st_dev == dest_stat.st_dev &&
        source_stat.st_ino == dest_stat.st_ino) {
        close(sfd);
        return 0;
    }
    dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        snprintf(err, errlen, "open %s: %s", dest, strerror(errno));
        close(sfd);
        return -1;
    }
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (green_agentops_write_full(dfd, buf, (size_t)n) != 0) {
            snprintf(err, errlen, "write %s: %s", dest, strerror(errno));
            close(sfd);
            close(dfd);
            return -1;
        }
    }
    close(sfd);
    if (n < 0) {
        snprintf(err, errlen, "read %s: %s", script_file, strerror(errno));
        close(dfd);
        return -1;
    }
    fchmod(dfd, 0644);
    {
        char proc_path[64];
        struct stat pst;
        snprintf(proc_path, sizeof(proc_path), "/proc/%d", (int)pid);
        if (stat(proc_path, &pst) == 0)
            fchown(dfd, pst.st_uid, pst.st_gid);
    }
    close(dfd);
    return 0;
}

int green_agentops_attach_and_load(pid_t pid, const char *script_file,
                                   const char *inline_code)
{
    char err[192] = {0};
    char dest[300];
    struct green_agent_response response;
    int cmd_fd;
    int broker_fd;
    int r;

    if (green_agentops_ensure_injected(pid, err, sizeof(err)) != 0) {
        fprintf(stderr, "hook: %s\n", err);
        return 1;
    }
    if (green_agentops_deploy_script(pid, script_file, inline_code, dest,
                                     sizeof(dest), err, sizeof(err)) != 0) {
        fprintf(stderr, "hook: %s\n", err);
        return 1;
    }
    fprintf(stderr, "hook: script -> %s\n", dest);

    /* conn A: the command; conn B: the broker serving the payload's
     * privileged page-table requests while the script evaluates. */
    cmd_fd = green_agentops_connect(pid);
    if (cmd_fd < 0)
        return 1;
    broker_fd = green_agentops_connect(pid);
    if (broker_fd < 0) {
        close(cmd_fd);
        return 1;
    }
    if (green_agentops_broker_attach(pid, broker_fd) != 0) {
        close(cmd_fd);
        close(broker_fd);
        return 1;
    }
    if (green_agentops_send_request(cmd_fd, GREEN_AGENT_TOOL_JS,
                                    GREEN_AGENT_CMD_JS_LOAD, 0, 0, 0) != 0) {
        close(cmd_fd);
        close(broker_fd);
        return 1;
    }

    for (;;) {
        struct pollfd fds[2] = {
            { .fd = broker_fd, .events = POLLIN },
            { .fd = cmd_fd, .events = POLLIN },
        };

        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (fds[0].revents & POLLIN) {
            if (green_agentops_broker_serve_one(pid, broker_fd, NULL,
                                                NULL) != 0)
                break;
        }
        if (fds[1].revents & POLLIN) {
            if (green_agentops_read_response(cmd_fd, &response) != 0)
                break;
            printf("status=%d value=0x%" PRIx64 " %s\n", response.status,
                   response.value, response.message);
            r = response.status == 0 ? 0 : 1;
            close(cmd_fd);
            close(broker_fd);
            return r;
        }
    }

    close(cmd_fd);
    close(broker_fd);
    return 1;
}
