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

static int send_result(int fd, int32_t ok, const char *msg)
{
    unsigned char buf[8 + 256];
    uint32_t len = (uint32_t)strlen(msg);

    if (len > sizeof(buf) - 8)
        len = sizeof(buf) - 8;
    put_u32(buf + 0, (uint32_t)ok);
    put_u32(buf + 4, len);
    memcpy(buf + 8, msg, len);
    return write_frame(fd, GREEN_WIRE_RESULT, buf, 8 + len);
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
            send_result(fd, 0, "no running process for package");
            free(script);
            return;
        }
        pid = (int32_t)found;
    }
    s.pid = (pid_t)pid;

    if (green_agentops_ensure_injected(s.pid, err, sizeof(err)) != 0) {
        send_result(fd, 0, err);
        free(script);
        return;
    }
    if (green_agentops_deploy_script(s.pid, NULL, script, dest, sizeof(dest),
                                     err, sizeof(err)) != 0) {
        send_result(fd, 0, err);
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
        send_result(fd, 0, "broker attach failed");
        free(script);
        return;
    }

    cmd_fd = green_agentops_connect(s.pid);
    if (cmd_fd < 0 ||
        green_agentops_send_request(cmd_fd, GREEN_AGENT_TOOL_JS,
                                    GREEN_AGENT_CMD_JS_LOAD, 0, 0, 0) != 0) {
        send_result(fd, 0, "agent request failed");
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
            send_result(fd, response.status == 0 ? 1 : 0, response.message);
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
            send_result(fd, 0, "spawn is not implemented yet");
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

static void server_usage(const char *prog)
{
    fprintf(stderr,
            "Green server: frida-style daemon driving the agent payload\n\n"
            "Usage:\n"
            "  %s server [--port PORT]\n\n"
            "Defaults: port %d, all interfaces.\n"
            "Host side: adb forward tcp:%d tcp:%d, then run cli/green.py\n",
            prog, GREEN_WIRE_DEFAULT_PORT, GREEN_WIRE_DEFAULT_PORT,
            GREEN_WIRE_DEFAULT_PORT);
}

int green_server_main(int argc, char **argv)
{
    struct sockaddr_in address;
    int listen_fd;
    int port = GREEN_WIRE_DEFAULT_PORT;
    int i;
    int one = 1;

    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else {
            server_usage(argv[0]);
            return 2;
        }
    }

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

const struct green_cli_tool green_cli_server_tool = {
    .name = "server",
    .summary = "run the frida-style daemon for host CLIs (default port 27042)",
    .main = green_server_main,
    .usage = server_usage,
};
