/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared agent-driving primitives: ptrace injector, control protocol client,
 * and root-side token provisioning used by `green hook` and `green server`.
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
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/un.h>
#include <stddef.h>
#include <pthread.h>
#include <unistd.h>

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

static unsigned long green_agentops_new_token(void)
{
    unsigned long token = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        ssize_t n = read(fd, &token, sizeof(token));
        close(fd);
        if (n == (ssize_t)sizeof(token) && token != 0)
            return token;
    }
    /* Never downgrade to a predictable token: shadow remains unavailable
     * until the root daemon can read the platform CSPRNG. */
    return 0;
}

#define GREEN_AGENT_TOKEN_SLOTS 64

struct green_agent_token_slot {
    pid_t pid;
    unsigned long token;
};

static struct green_agent_token_slot green_agent_token_slots[
    GREEN_AGENT_TOKEN_SLOTS];
static pthread_mutex_t green_agent_token_lock = PTHREAD_MUTEX_INITIALIZER;

static struct green_agent_token_slot *
green_agentops_find_token_locked(pid_t pid)
{
    size_t i;

    for (i = 0; i < GREEN_AGENT_TOKEN_SLOTS; i++) {
        if (green_agent_token_slots[i].pid == pid)
            return &green_agent_token_slots[i];
    }
    return NULL;
}

static struct green_agent_token_slot *
green_agentops_reserve_token_locked(pid_t pid, unsigned long candidate)
{
    size_t i;
    struct green_agent_token_slot *free_slot = NULL;

    for (i = 0; i < GREEN_AGENT_TOKEN_SLOTS; i++) {
        if (green_agent_token_slots[i].pid == pid)
            return &green_agent_token_slots[i];
        if (free_slot == NULL && green_agent_token_slots[i].pid == 0)
            free_slot = &green_agent_token_slots[i];
    }
    if (free_slot != NULL) {
        free_slot->pid = pid;
        free_slot->token = candidate;
    }
    return free_slot;
}

static void green_agentops_drop_token(pid_t pid, unsigned long token)
{
    struct green_agent_token_slot *slot;

    pthread_mutex_lock(&green_agent_token_lock);
    slot = green_agentops_find_token_locked(pid);
    if (slot != NULL && (token == 0 || slot->token == token))
        memset(slot, 0, sizeof(*slot));
    pthread_mutex_unlock(&green_agent_token_lock);
}

int green_agentops_revoke(pid_t pid, unsigned long token)
{
    long ret = green_cli_prctl(PR_GREEN_SHADOW_TOKEN_REVOKE,
                               (unsigned long)pid, token, 0, 0);
    green_agentops_drop_token(pid, token);
    return ret < 0 ? (int)ret : 0;
}

int green_agentops_authorize(pid_t pid, unsigned long *token,
                             char *err, size_t errlen)
{
    struct green_agent_response response;
    unsigned long candidate;
    long ret;
    int fd = -1;

    if (!token || pid <= 0)
        return -EINVAL;
    pthread_mutex_lock(&green_agent_token_lock);
    {
        struct green_agent_token_slot *slot =
            green_agentops_find_token_locked(pid);
        if (slot != NULL)
            candidate = slot->token;
        else {
            candidate = green_agentops_new_token();
            if (candidate != 0 &&
                green_agentops_reserve_token_locked(pid, candidate) == NULL)
                candidate = 0;
        }
    }
    if (candidate == 0) {
        pthread_mutex_unlock(&green_agent_token_lock);
        snprintf(err, errlen, "cannot obtain a secure shadow token");
        return -EAGAIN;
    }
    ret = green_cli_prctl(PR_GREEN_SHADOW_TOKEN_REGISTER,
                          (unsigned long)pid, candidate, 0, 0);
    pthread_mutex_unlock(&green_agent_token_lock);
    if (ret < 0) {
        green_agentops_drop_token(pid, candidate);
        snprintf(err, errlen,
                 "KPM shadow token registration failed (%ld); load green.kpm first",
                 ret);
        return (int)ret;
    }
    if (green_agentops_ensure_injected(pid, candidate, err, errlen) != 0) {
        (void)green_agentops_revoke(pid, candidate);
        return -1;
    }
    memset(&response, 0, sizeof(response));
    fd = green_agentops_connect(pid);
    if (fd < 0 ||
        green_agentops_send_request(fd, GREEN_AGENT_TOOL_CORE,
                                    GREEN_AGENT_CMD_SHADOW_TOKEN_SET,
                                    candidate, 0, 0) != 0 ||
        green_agentops_read_response(fd, &response) != 0 ||
        response.status != 0) {
        if (fd >= 0)
            close(fd);
        (void)green_agentops_revoke(pid, candidate);
        snprintf(err, errlen, "agent rejected shadow token: %s",
                 response.message[0] ? response.message : "control connection failed");
        return -EACCES;
    }
    close(fd);
    *token = candidate;
    fprintf(stderr, "hook: shadow token provisioned for pid %d\n", (int)pid);
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

static int shadow_write_target(pid_t pid, unsigned long token,
                               uintptr_t address, const void *data,
                               size_t size)
{
    if (token == 0 || data == NULL || size == 0 ||
        address > UINTPTR_MAX - size)
        return -1;

    /* The KPM ABI is page-bounded.  Do not retain a direct-write fallback:
     * even the temporary dlopen pathname used by the injector must obey the
     * same authenticated shadow policy as agent code patches. */
    while (size != 0) {
        struct green_shadow_rpc rpc;
        size_t chunk = 4096 - (address & 4095U);
        long ret;

        if (chunk > size)
            chunk = size;
        memset(&rpc, 0, sizeof(rpc));
        rpc.version = GREEN_SHADOW_ABI_VERSION;
        rpc.op = GREEN_SHADOW_OP_PATCH;
        rpc.pid = (int)pid;
        rpc.addr = (unsigned long)address;
        rpc.buf = (unsigned long)data;
        rpc.len = (unsigned long)chunk;
        ret = green_cli_prctl(PR_GREEN_SHADOW_REQUEST, token,
                              (unsigned long)&rpc, 0, 0);
        if (ret < 0) {
            errno = (int)(-ret);
            return -1;
        }
        address += chunk;
        data = (const char *)data + chunk;
        size -= chunk;
    }
    return 0;
}

static int shadow_release_target(pid_t pid, unsigned long token,
                                 uintptr_t address)
{
    struct green_shadow_rpc rpc;
    long ret;

    if (token == 0 || address == 0)
        return -1;
    memset(&rpc, 0, sizeof(rpc));
    rpc.version = GREEN_SHADOW_ABI_VERSION;
    rpc.op = GREEN_SHADOW_OP_RELEASE;
    rpc.pid = (int)pid;
    rpc.addr = (unsigned long)address;
    ret = green_cli_prctl(PR_GREEN_SHADOW_REQUEST, token,
                          (unsigned long)&rpc, 0, 0);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
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

static int remote_dlopen(pid_t pid, const char *payload,
                         unsigned long shadow_token)
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
    bool path_shadowed = false;

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

    /* Keep the temporary pathname in the already-populated page containing
     * the stopped thread's stack pointer.  A far-below-SP address can be a
     * valid VMA address but have no present PTE yet; KPM shadow intentionally
     * refuses to fabricate such pages.  The call frame grows below SP, so a
     * small slot immediately below the saved SP remains out of the live
     * frame while still being mapped. */
    if (get_regs(pid, &saved) != 0)
        return -1;
    if (saved.sp < 0x200)
        return -1;
    remote_path = (saved.sp - 0x100) & ~(uintptr_t)0xf;
    if (shadow_write_target(pid, shadow_token, remote_path, payload,
                            payload_len) != 0) {
        perror("shadow-write remote payload path");
        return -1;
    }
    path_shadowed = true;
    if (get_regs(pid, &saved) != 0)
        goto restore;
    call = saved;
    call.regs[0] = remote_path;
    call.regs[1] = RTLD_NOW | RTLD_GLOBAL;
    call.sp = remote_path & ~(uintptr_t)0xf;
    call.regs[30] = 0; /* return to address 0; ptrace catches SIGSEGV */
    call.pc = remote_dlopen;
    if (set_regs(pid, &call) != 0)
        goto restore;

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
    if (path_shadowed &&
        shadow_release_target(pid, shadow_token, remote_path) != 0) {
        perror("shadow-release remote payload path");
        result = -1;
    }
    return result;
}

int green_agentops_inject(pid_t pid, const char *so_path,
                          unsigned long shadow_token)
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
    if (remote_dlopen(pid, so_path, shadow_token) == 0) {
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
    const char *app_dir;

    if (slash) {
        /* Non-app target: deploy next to its executable. */
        size_t dir_len = (size_t)(slash - cmdline) + 1;
        snprintf(out, out_size, "%.*s%s", (int)dir_len, cmdline, file);
    } else {
        base_package(cmdline, package, sizeof(package));
        /* Android may mount the ordinary cache directory noexec.  Keep
         * scripts/eval data in cache, but put the ELF payload in code_cache,
         * which is the app-private executable cache used by ART. */
        app_dir = (file && strcmp(file, "libgreen_agent.so") == 0)
            ? "code_cache" : "cache";
        snprintf(out, out_size, "/data/user/0/%s/%s/%s", package,
                 app_dir, file ? file : "");
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
    dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
               mode);
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

int green_agentops_ensure_injected(pid_t pid, unsigned long shadow_token,
                                   char *err, size_t errlen)
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

    if (green_agentops_inject(pid, so_path, shadow_token) != 0) {
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
        dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                   0644);
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
    dfd = open(dest, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
               0644);
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
