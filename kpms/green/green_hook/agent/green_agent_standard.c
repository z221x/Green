/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Standard GumJS host for Green.
 *
 * The payload is still controlled through the small Green control socket, but
 * script execution is provided by GumScriptBackend/GumQuickScript.  There is
 * no page-operation broker: gum_memory_* calls the authenticated direct KPM
 * shadow client in green_shadow_client.c.
 */

#include "green_agent.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gumjs/gumscript.h>
#include <gumjs/gumscriptbackend.h>
#include <gumjs/gumscriptscheduler.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define AGLOG(...) __android_log_print(ANDROID_LOG_INFO, "green-agent", __VA_ARGS__)
#define GREEN_AGENT_MAX_SCRIPT_SIZE (4U * 1024U * 1024U)

#include "fjb.inc"

static GumScriptBackend *g_backend;
static GumScript *g_script;
static pthread_mutex_t g_script_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_eval_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_eval_cond = PTHREAD_COND_INITIALIZER;
static int g_eval_active;
static int g_eval_done;
static char g_eval_message[GREEN_AGENT_MAX_MESSAGE];
static int g_event_fd = -1;
static int g_server_fd = -1;

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

static void response_init(struct green_agent_response *response)
{
    memset(response, 0, sizeof(*response));
    response->magic = GREEN_AGENT_MAGIC;
    response->version = GREEN_AGENT_VERSION;
    response->size = sizeof(*response);
}

static int peer_is_root(int fd)
{
    struct ucred cred;
    socklen_t size = sizeof(cred);

    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &size) == 0 &&
           cred.uid == 0;
}

static void emit_message(const gchar *message, GBytes *data, gpointer user_data)
{
    struct green_agent_response event;
    size_t n;

    (void)data;
    (void)user_data;
    pthread_mutex_lock(&g_eval_lock);
    if (g_eval_active && message != NULL &&
        strstr(message, "green-eval-result") != NULL) {
        size_t n = strlen(message);
        if (n >= sizeof(g_eval_message))
            n = sizeof(g_eval_message) - 1;
        memcpy(g_eval_message, message, n);
        g_eval_message[n] = '\0';
        g_eval_done = 1;
        pthread_cond_signal(&g_eval_cond);
        pthread_mutex_unlock(&g_eval_lock);
        return;
    }
    pthread_mutex_unlock(&g_eval_lock);
    __android_log_print(ANDROID_LOG_INFO, "green-js", "%s",
                        message ? message : "");

    pthread_mutex_lock(&g_io_lock);
    if (g_event_fd >= 0 && message != NULL) {
        response_init(&event);
        event.status = GREEN_AGENT_STATUS_EVENT;
        n = strlen(message);
        if (n >= sizeof(event.message))
            n = sizeof(event.message) - 1;
        memcpy(event.message, message, n);
        event.message[n] = '\0';
        if (write_full(g_event_fd, &event, sizeof(event)) != 0) {
            close(g_event_fd);
            g_event_fd = -1;
        }
    }
    pthread_mutex_unlock(&g_io_lock);
}

static char *json_quote(const char *source)
{
    size_t n = 2;
    const unsigned char *p;
    char *out, *q;

    for (p = (const unsigned char *)source; *p; p++)
        n += (*p == '\\' || *p == '"' || *p < 0x20) ? 2 : 1;
    out = malloc(n + 1);
    if (!out)
        return NULL;
    q = out;
    *q++ = '"';
    for (p = (const unsigned char *)source; *p; p++) {
        switch (*p) {
        case '\\': *q++ = '\\'; *q++ = '\\'; break;
        case '"': *q++ = '\\'; *q++ = '"'; break;
        case '\n': *q++ = '\\'; *q++ = 'n'; break;
        case '\r': *q++ = '\\'; *q++ = 'r'; break;
        case '\t': *q++ = '\\'; *q++ = 't'; break;
        default:
            if (*p < 0x20) { *q++ = ' '; } else { *q++ = (char)*p; }
            break;
        }
    }
    *q++ = '"';
    *q = '\0';
    return out;
}

static int read_script(const char *path, char **out, size_t *out_len)
{
    struct stat st;
    char *source;
    int fd;
    ssize_t n;
    size_t used = 0;

    if (stat(path, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > GREEN_AGENT_MAX_SCRIPT_SIZE)
        return -EINVAL;
    source = malloc((size_t)st.st_size + 1);
    if (!source)
        return -ENOMEM;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free(source);
        return -errno;
    }
    while (used < (size_t)st.st_size) {
        n = read(fd, source + used, (size_t)st.st_size - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(fd);
    if (used != (size_t)st.st_size) {
        free(source);
        return -EIO;
    }
    source[used] = '\0';
    *out = source;
    *out_len = used;
    return 0;
}

static void target_script_path(char *out, size_t out_size)
{
    char cmdline[256] = {0};
    char package[192] = {0};
    const char *colon;
    const char *slash;
    int fd;
    ssize_t n;

    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n > 0)
            cmdline[n] = '\0';
    }
    slash = strrchr(cmdline, '/');
    if (slash != NULL) {
        snprintf(out, out_size, "%.*s%s", (int)(slash - cmdline + 1),
                 cmdline, GREEN_AGENT_SCRIPT_NAME);
        return;
    }
    colon = strchr(cmdline, ':');
    if (colon != NULL)
        snprintf(package, sizeof(package), "%.*s", (int)(colon - cmdline),
                 cmdline);
    else
        snprintf(package, sizeof(package), "%s", cmdline);
    snprintf(out, out_size, "/data/user/0/%s/cache/%s", package,
             GREEN_AGENT_SCRIPT_NAME);
}

static int ensure_backend(void)
{
    if (g_backend != NULL)
        return 0;

    g_backend = gum_script_backend_obtain_qjs();
    if (g_backend == NULL)
        return -ENOMEM;
    gum_script_scheduler_enable_background_thread(
        gum_script_backend_get_scheduler());
    return 0;
}

static int load_script(const char *path, char *message, size_t message_size)
{
    static const char glue[] =
        "globalThis.Java = globalThis.__fjb.default; "
        "delete globalThis.__fjb; "
        "try { Java.vm.attachCurrentThread(); } catch (e) {} "
        "try { var __env = Java.vm.getEnv(); "
        "var __ep = Object.getPrototypeOf(__env); "
        "__ep.releaseStringChars = function () {}; "
        "__ep.releaseStringUTFChars = function () {}; } catch (e) {}\n"
        "(function () { function arm() { recv('green:eval', function (m) { "
        "try { send({type:'green-eval-result', ok:true, value:Script.evaluate('green-eval', m.payload.source)}); } "
        "catch (e) { send({type:'green-eval-result', ok:false, error:String(e)}); } arm(); }); } arm(); })();\n";
    char *user_source = NULL;
    char *source = NULL;
    size_t user_len = 0;
    size_t source_len;
    GumScript *new_script = NULL;
    GError *error = NULL;
    int ret;

    ret = read_script(path, &user_source, &user_len);
    if (ret != 0) {
        snprintf(message, message_size, "cannot read %s: %d", path, ret);
        return ret;
    }
    source_len = strlen(kFjbBundle) + strlen(glue) + user_len + 2;
    source = malloc(source_len + 1);
    if (!source) {
        free(user_source);
        return -ENOMEM;
    }
    snprintf(source, source_len + 1, "%s\n%s\n%.*s", kFjbBundle, glue,
             (int)user_len, user_source);
    free(user_source);

    pthread_mutex_lock(&g_script_lock);
    ret = ensure_backend();
    if (ret == 0) {
        new_script = gum_script_backend_create_sync(
            g_backend, GREEN_AGENT_SCRIPT_NAME, source, NULL, NULL, &error);
        if (new_script == NULL)
            ret = -EIO;
    }
    if (ret == 0) {
        gum_script_set_message_handler(new_script, emit_message, NULL, NULL);
        gum_script_load_sync(new_script, NULL);
        if (g_script != NULL) {
            gum_script_unload_sync(g_script, NULL);
            g_object_unref(g_script);
        }
        g_script = new_script;
        new_script = NULL;
        snprintf(message, message_size, "standard GumJS loaded from %s", path);
    } else if (error != NULL) {
        snprintf(message, message_size, "GumJS error: %s", error->message);
    } else {
        snprintf(message, message_size, "GumJS load failed: %d", ret);
    }
    if (new_script != NULL)
        g_object_unref(new_script);
    if (error != NULL)
        g_error_free(error);
    pthread_mutex_unlock(&g_script_lock);
    free(source);
    return ret;
}

static int evaluate_file(const char *path, char *message, size_t message_size)
{
    char *source = NULL;
    char *quoted = NULL;
    char *request = NULL;
    size_t source_len = 0;
    size_t request_len;
    struct timespec deadline;
    int ret;

    if (g_script == NULL) {
        snprintf(message, message_size, "no script is loaded");
        return -ENOENT;
    }
    ret = read_script(path, &source, &source_len);
    if (ret != 0)
        return ret;
    quoted = json_quote(source);
    free(source);
    if (!quoted)
        return -ENOMEM;
    request_len = strlen("{\"type\":\"green:eval\",\"payload\":{\"source\":}}") +
                  strlen(quoted);
    request = malloc(request_len + 1);
    if (!request) {
        free(quoted);
        return -ENOMEM;
    }
    snprintf(request, request_len + 1,
             "{\"type\":\"green:eval\",\"payload\":{\"source\":%s}}",
             quoted);
    free(quoted);

    pthread_mutex_lock(&g_eval_lock);
    g_eval_active = 1;
    g_eval_done = 0;
    g_eval_message[0] = '\0';
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    pthread_mutex_unlock(&g_eval_lock);
    gum_script_post(g_script, request, NULL);
    pthread_mutex_lock(&g_eval_lock);
    while (!g_eval_done &&
           pthread_cond_timedwait(&g_eval_cond, &g_eval_lock, &deadline) == 0)
        ;
    if (!g_eval_done) {
        g_eval_active = 0;
        pthread_mutex_unlock(&g_eval_lock);
        free(request);
        snprintf(message, message_size, "JavaScript evaluation timed out");
        return -ETIMEDOUT;
    }
    snprintf(message, message_size, "%s", g_eval_message);
    ret = strstr(g_eval_message, "\"ok\":true") != NULL ? 0 : -EFAULT;
    g_eval_active = 0;
    pthread_mutex_unlock(&g_eval_lock);
    free(request);
    return ret;
}

static int dispatch(int fd, const struct green_agent_request *request,
                    struct green_agent_response *response)
{
    char path[512];
    int status;

    if (request->tool != GREEN_AGENT_TOOL_CORE && !peer_is_root(fd))
        return -EPERM;
    if (request->tool == GREEN_AGENT_TOOL_CORE) {
        if (request->command == GREEN_AGENT_CMD_PING) {
            response->value = (uint64_t)getpid();
            snprintf(response->message, sizeof(response->message),
                     "standard GumJS agent ready pid=%d", (int)getpid());
            return 0;
        }
        if (request->command == GREEN_AGENT_CMD_SHADOW_TOKEN_SET) {
            if (!peer_is_root(fd) || request->arg0 == 0)
                return -EPERM;
            green_agent_set_shadow_token((unsigned long)request->arg0);
            response->value = request->arg0;
            snprintf(response->message, sizeof(response->message),
                     "shadow token accepted");
            return 0;
        }
        return -EOPNOTSUPP;
    }
    if (request->tool != GREEN_AGENT_TOOL_JS)
        return -EOPNOTSUPP;

    target_script_path(path, sizeof(path));
    if (request->command == GREEN_AGENT_CMD_JS_EVAL) {
        int eval_status;
        int old_event_fd;
        pthread_mutex_lock(&g_io_lock);
        old_event_fd = g_event_fd;
        g_event_fd = fd;
        pthread_mutex_unlock(&g_io_lock);
        pthread_mutex_lock(&g_script_lock);
        eval_status = evaluate_file(path, response->message,
                                    sizeof(response->message));
        pthread_mutex_unlock(&g_script_lock);
        pthread_mutex_lock(&g_io_lock);
        if (g_event_fd == fd)
            g_event_fd = old_event_fd;
        pthread_mutex_unlock(&g_io_lock);
        return eval_status;
    }
    if (request->command != GREEN_AGENT_CMD_JS_LOAD)
        return -EOPNOTSUPP;
    pthread_mutex_lock(&g_io_lock);
    g_event_fd = fd;
    pthread_mutex_unlock(&g_io_lock);
    status = load_script(path, response->message, sizeof(response->message));
    if (status != 0) {
        pthread_mutex_lock(&g_io_lock);
        if (g_event_fd == fd)
            g_event_fd = -1;
        pthread_mutex_unlock(&g_io_lock);
    }
    return status;
}

static void *client_main(void *data)
{
    int fd = *(int *)data;
    struct green_agent_request request;
    struct green_agent_response response;
    free(data);

    for (;;) {
        if (read_full(fd, &request, sizeof(request)) != 0)
            break;
        response_init(&response);
        if (request.magic != GREEN_AGENT_MAGIC ||
            request.version != GREEN_AGENT_VERSION ||
            request.size != sizeof(request)) {
            response.status = -EPROTO;
        } else {
            response.status = dispatch(fd, &request, &response);
        }
        pthread_mutex_lock(&g_io_lock);
        if (write_full(fd, &response, sizeof(response)) != 0) {
            pthread_mutex_unlock(&g_io_lock);
            break;
        }
        pthread_mutex_unlock(&g_io_lock);
    }
    pthread_mutex_lock(&g_io_lock);
    if (g_event_fd == fd)
        g_event_fd = -1;
    pthread_mutex_unlock(&g_io_lock);
    close(fd);
    return NULL;
}

static void *server_main(void *unused)
{
    struct sockaddr_un address;
    char name[sizeof(address.sun_path) - 1];
    int name_len;

    (void)unused;
    name_len = green_agent_socket_name(getpid(), name, sizeof(name));
    if (name_len < 0)
        return NULL;
    g_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_server_fd < 0)
        return NULL;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, (size_t)name_len);
    if (bind(g_server_fd, (struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                         name_len)) != 0 || listen(g_server_fd, 4) != 0) {
        close(g_server_fd);
        g_server_fd = -1;
        return NULL;
    }
    for (;;) {
        int fd = accept(g_server_fd, NULL, NULL);
        int *arg;
        pthread_t thread;

        if (fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        arg = malloc(sizeof(*arg));
        if (!arg) {
            close(fd);
            continue;
        }
        *arg = fd;
        if (pthread_create(&thread, NULL, client_main, arg) == 0)
            pthread_detach(thread);
        else
            close(fd);
    }
    return NULL;
}

__attribute__((constructor)) static void green_agent_constructor(void)
{
    pthread_t thread;
    extern void glib_init(void);
    extern void gum_init_embedded(void);

    glib_init();
    gum_init_embedded();
    if (pthread_create(&thread, NULL, server_main, NULL) == 0)
        pthread_detach(thread);
}
