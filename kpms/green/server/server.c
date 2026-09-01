/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * `green server`: frida-server-style daemon.  Listens on TCP (default
 * 27042) and drives the in-process agent payload on behalf of a host CLI:
 *
 *   LIST   enumerate running processes;
 *   ATTACH resolve target, inject libgreen_agent.so when needed, deploy
 *          the hook script and evaluate it, then stream script logs back
 *          to the host while the broker channel stays attached;
 *   SPAWN  reserved (not implemented yet).
 *
 * Wire protocol (see include/green/wire.h): frames of
 *   u32 magic, u16 type, u16 flags, u32 payload_len, payload
 * with all integers LITTLE-ENDIAN.
 */

#include <green/agentops.h>
#include <green/abi.h>
#include <green/cli.h>
#include <green/wire.h>
#include <green_agent.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>

static void put_u32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static uint32_t get_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int read_full_fd(int fd, void *buf, size_t size)
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

static int write_full_fd(int fd, const void *buf, size_t size)
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

static int write_frame(int fd, uint16_t type, const void *payload,
                       uint32_t len)
{
    unsigned char header[12];

    put_u32(header + 0, GREEN_WIRE_MAGIC);
    put_u32(header + 4, (uint32_t)type);
    put_u32(header + 8, len);
    if (write_full_fd(fd, header, sizeof(header)) != 0)
        return -1;
    if (len != 0 && write_full_fd(fd, payload, len) != 0)
        return -1;
    return 0;
}

static int send_result(int fd, int32_t ok, int64_t value, const char *msg)
{
    unsigned char buf[20 + 256];
    uint32_t len = (uint32_t)strlen(msg);

    if (len > sizeof(buf) - 20)
        len = sizeof(buf) - 20;
    put_u32(buf + 0, (uint32_t)ok);
    put_u32(buf + 4, 0); /* reserved */
    put_u32(buf + 8, (uint32_t)(uint64_t)value);
    put_u32(buf + 12, (uint32_t)((uint64_t)value >> 32));
    put_u32(buf + 16, len);
    memcpy(buf + 20, msg, len);
    return write_frame(fd, GREEN_WIRE_RESULT, buf, 20 + len);
}

struct session {
    int host_fd;
    pid_t pid;
    pthread_mutex_t send_lock; /* guards host_fd writes from pump + owner */
};

static void session_log_cb(int32_t pid, const char *text, uint32_t len,
                           void *ud)
{
    struct session *s = ud;
    unsigned char *buf;
    uint32_t n = len;

    if (n > 8192)
        n = 8192;
    buf = malloc(8 + n);
    if (!buf)
        return;
    put_u32(buf + 0, (uint32_t)pid);
    put_u32(buf + 4, n);
    memcpy(buf + 8, text, n);
    pthread_mutex_lock(&s->send_lock);
    write_frame(s->host_fd, GREEN_WIRE_LOG, buf, 8 + n);
    pthread_mutex_unlock(&s->send_lock);
    free(buf);
}

static int handle_list(int fd)
{
    DIR *dir;
    struct dirent *de;
    unsigned char *buf;
    size_t cap = 64 * 1024;
    size_t used = 4;
    uint32_t count = 0;

    buf = malloc(cap);
    if (!buf)
        return -1;

    dir = opendir("/proc");
    while (dir && (de = readdir(dir)) != NULL) {
        char cmdline[128];
        char name[128];
        pid_t pid;
        size_t name_len;

        if (de->d_name[0] < '0' || de->d_name[0] > '9')
            continue;
        pid = (pid_t)atoi(de->d_name);
        if (pid <= 0)
            continue;
        if (green_agentops_read_cmdline(pid, cmdline, sizeof(cmdline)) != 0 ||
            cmdline[0] == '\0')
            snprintf(name, sizeof(name), "(pid %d)", (int)pid);
        else
            snprintf(name, sizeof(name), "%s", cmdline);
        name_len = strlen(name);
        if (name_len > 255)
            name_len = 255;
        if (used + 4 + 2 + name_len + 8 > cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (!buf)
                break;
        }
        put_u32(buf + used, (uint32_t)pid);
        used += 4;
        buf[used++] = (unsigned char)(name_len & 0xff);
        buf[used++] = (unsigned char)((name_len >> 8) & 0xff);
        memcpy(buf + used, name, name_len);
        used += name_len;
        count++;
    }
    if (dir)
        closedir(dir);
    put_u32(buf, count);

    write_frame(fd, GREEN_WIRE_PROCS, buf, (uint32_t)used);
    free(buf);
    return 0;
}

/* ATTACH payload: i32 pid | u8 has_package | char package[128] |
 * u32 script_len | script bytes. */
#define ATTACH_HDR 137

static void handle_attach(int fd, const unsigned char *payload, uint32_t len)
{
    struct session s;
    struct green_agent_response response;
    char package[128] = {0};
    char err[192] = {0};
    char dest[300];
    char *script = NULL;
    int32_t pid = 0;
    uint8_t has_package;
    uint32_t script_len;
    int broker_fd = -1;
    int cmd_fd = -1;
    int ok = 0;

    if (len < ATTACH_HDR)
        return;
    pid = (int32_t)get_u32(payload + 0);
    has_package = payload[4];
    memcpy(package, payload + 5, sizeof(package) - 1);
    script_len = get_u32(payload + 133);
    if (len - ATTACH_HDR < script_len)
        return;
    script = malloc((size_t)script_len + 1);
    if (!script)
        return;
    memcpy(script, payload + ATTACH_HDR, script_len);
    script[script_len] = '\0';

    memset(&s, 0, sizeof(s));
    s.host_fd = fd;
    pthread_mutex_init(&s.send_lock, NULL);

    if (has_package) {
        pid_t found = green_agentops_find_package(package);

        if (found <= 0) {
            send_result(fd, 0, 0, "no running process for package");
            free(script);
            return;
        }
        pid = (int32_t)found;
    }
    s.pid = (pid_t)pid;

    if (green_agentops_ensure_injected(s.pid, err, sizeof(err)) != 0) {
        send_result(fd, 0, 0, err);
        free(script);
        return;
    }
    if (green_agentops_deploy_script(s.pid, NULL, script, dest, sizeof(dest),
                                     err, sizeof(err)) != 0) {
        send_result(fd, 0, 0, err);
        free(script);
        return;
    }

    /* Attach the broker before evaluating: hook() inside the script needs
     * it, and it stays attached afterwards so logs keep streaming. */
    broker_fd = green_agentops_connect(s.pid);
    if (broker_fd < 0 ||
        green_agentops_broker_attach(s.pid, broker_fd) != 0) {
        if (broker_fd >= 0)
            close(broker_fd);
        send_result(fd, 0, 0, "broker attach failed");
        free(script);
        return;
    }

    cmd_fd = green_agentops_connect(s.pid);
    if (cmd_fd < 0 ||
        green_agentops_send_request(cmd_fd, GREEN_AGENT_TOOL_JS,
                                    GREEN_AGENT_CMD_JS_LOAD, 0, 0, 0) != 0) {
        send_result(fd, 0, 0, "agent request failed");
        goto out;
    }

    /* Serve broker traffic while the LOAD request runs (hook() inside the
     * script blocks on its PATCH response). */
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
            if (green_agentops_broker_serve_one(s.pid, broker_fd,
                                                session_log_cb, &s) != 0)
                break;
        }
        if (fds[1].revents & POLLIN) {
            if (green_agentops_read_response(cmd_fd, &response) != 0)
                break;
            pthread_mutex_lock(&s.send_lock);
            send_result(fd, response.status == 0 ? 1 : 0,
                        (int64_t)response.value, response.message);
            pthread_mutex_unlock(&s.send_lock);
            ok = response.status == 0;
            break;
        }
    }

    if (ok) {
        /* Keep streaming script logs until the host disconnects. */
        for (;;) {
            if (green_agentops_broker_serve_one(s.pid, broker_fd,
                                                session_log_cb, &s) != 0)
                break;
        }
    }

out:
    free(script);
    if (cmd_fd >= 0)
        close(cmd_fd);
    if (broker_fd >= 0)
        close(broker_fd);
}


/* ---- host-driven shadow operations (run here, on the device, as root) */

struct module_list_ctx {
    unsigned char *buf;
    size_t cap;
    size_t used;
    uint32_t count;
};

static int module_list_cb(const char *name, unsigned long base,
                          unsigned long size, void *ud)
{
    struct module_list_ctx *m = ud;
    size_t name_len = strlen(name);
    size_t need = 8 + 2 + name_len;

    if (m->used + need + 16 > m->cap) {
        m->cap = m->cap * 2 + need;
        m->buf = realloc(m->buf, m->cap);
        if (!m->buf)
            return -1;
    }
    m->buf[m->used++] = (unsigned char)(base & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 8) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 16) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 24) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 32) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 40) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 48) & 0xff);
    m->buf[m->used++] = (unsigned char)((base >> 56) & 0xff);
    /* size stored as u64 */
    m->buf[m->used++] = (unsigned char)(size & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 8) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 16) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 24) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 32) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 40) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 48) & 0xff);
    m->buf[m->used++] = (unsigned char)((size >> 56) & 0xff);
    m->buf[m->used++] = (unsigned char)(name_len & 0xff);
    m->buf[m->used++] = (unsigned char)((name_len >> 8) & 0xff);
    memcpy(m->buf + m->used, name, name_len);
    m->used += name_len;
    m->count++;
    return 0;
}

static void handle_shadow_patch(int fd, const unsigned char *payload,
                                uint32_t len)
{
    int32_t pid;
    uint32_t plen;
    uint64_t addr;
    unsigned char bytes[4096];
    long ret;

    if (len < 16)
        return;
    pid = (int32_t)get_u32(payload + 0);
    plen = get_u32(payload + 4);
    addr = get_u32(payload + 8) | ((uint64_t)get_u32(payload + 12) << 32);
    if (plen == 0 || plen > sizeof(bytes) || len - 16 < plen) {
        send_result(fd, 0, 0, "invalid patch payload");
        return;
    }
    memcpy(bytes, payload + 16, plen);
    ret = green_cli_prctl(PR_GREEN_SHADOW_PATCH, (unsigned long)pid,
                          (unsigned long)addr, (unsigned long)bytes, plen);
    if (ret < 0)
        send_result(fd, 0, ret, strerror((int)-ret));
    else
        send_result(fd, 1, ret, "patched");
}

static void handle_shadow_release(int fd, const unsigned char *payload,
                                  uint32_t len)
{
    int32_t pid;
    uint64_t addr;
    long ret;
    char msg[96];

    if (len < 16)
        return;
    pid = (int32_t)get_u32(payload + 0);
    addr = get_u32(payload + 8) | ((uint64_t)get_u32(payload + 12) << 32);
    ret = green_cli_prctl(PR_GREEN_SHADOW_RELEASE, (unsigned long)pid,
                          (unsigned long)addr, 0, 0);
    if (ret < 0) {
        send_result(fd, 0, ret, strerror((int)-ret));
        return;
    }
    snprintf(msg, sizeof(msg), "released %ld shadow page(s) for pid %d", ret,
             (int)pid);
    send_result(fd, 1, ret, msg);
}

static void handle_shadow_count(int fd, const unsigned char *payload,
                                uint32_t len)
{
    int32_t pid;
    long ret;

    if (len < 4)
        return;
    pid = (int32_t)get_u32(payload + 0);
    ret = green_cli_prctl(PR_GREEN_SHADOW_COUNT, (unsigned long)pid, 0, 0, 0);
    if (ret < 0)
        send_result(fd, 0, ret, strerror((int)-ret));
    else
        send_result(fd, 1, ret, "ok");
}

static void handle_solist(int fd, const unsigned char *payload, uint32_t len)
{
    /* payload: i32 pid | u8 has_name | char name[128] (133 bytes, packed) */
    const uint32_t SOLIST_HDR = 133;
    struct module_list_ctx m;
    int32_t pid;
    uint32_t count;

    if (len < SOLIST_HDR)
        return;
    pid = (int32_t)get_u32(payload + 0);

    memset(&m, 0, sizeof(m));
    m.cap = 64 * 1024;
    m.buf = malloc(m.cap);
    if (!m.buf)
        return;
    put_u32(m.buf, 0);
    m.used = 4;

    if (green_cli_list_solist((pid_t)pid, module_list_cb, &m) == 0) {
        count = m.count;
        put_u32(m.buf, count);
        write_frame(fd, GREEN_WIRE_MODULES, m.buf, (uint32_t)m.used);
    } else {
        send_result(fd, 0, 0, "solist enumeration failed");
    }
    free(m.buf);
}

static void *conn_main(void *arg)
{
    int fd = (int)(intptr_t)arg;

    for (;;) {
        unsigned char header[12];
        unsigned char *payload;
        uint32_t magic, len;
        uint16_t type, flags;

        if (read_full_fd(fd, header, sizeof(header)) != 0)
            break;
        magic = get_u32(header + 0);
        type = (uint16_t)(get_u32(header + 4) & 0xffff);
        flags = (uint16_t)(get_u32(header + 4) >> 16);
        len = get_u32(header + 8);
        if (magic != GREEN_WIRE_MAGIC || len > 4u * 1024 * 1024)
            break;
        payload = malloc(len ? len : 1);
        if (!payload)
            break;
        if (len != 0 && read_full_fd(fd, payload, len) != 0) {
            free(payload);
            break;
        }

        switch (type) {
        case GREEN_WIRE_LIST:
            handle_list(fd);
            break;
        case GREEN_WIRE_ATTACH:
            handle_attach(fd, payload, len);
            break;
        case GREEN_WIRE_SPAWN:
            send_result(fd, 0, 0, "spawn is not implemented yet");
            break;
        case GREEN_WIRE_SHADOW_PATCH:
            handle_shadow_patch(fd, payload, len);
            break;
        case GREEN_WIRE_SHADOW_RELEASE:
            handle_shadow_release(fd, payload, len);
            break;
        case GREEN_WIRE_SHADOW_COUNT:
            handle_shadow_count(fd, payload, len);
            break;
        case GREEN_WIRE_SOLIST:
            handle_solist(fd, payload, len);
            break;
        default:
            break;
        }
        (void)flags;
        free(payload);
    }
    close(fd);
    return NULL;
}

int green_server_run(int port)
{
    struct sockaddr_in address;
    int listen_fd;
    int one = 1;

    signal(SIGPIPE, SIG_IGN);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }
    if (listen(listen_fd, 8) != 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }
    fprintf(stderr, "green server listening on 0.0.0.0:%d\n", port);

    for (;;) {
        int client = accept(listen_fd, NULL, NULL);
        pthread_t thread;

        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pthread_create(&thread, NULL, conn_main,
                           (void *)(intptr_t)client) == 0)
            pthread_detach(thread);
        else
            close(client);
    }
    close(listen_fd);
    return 0;
}
