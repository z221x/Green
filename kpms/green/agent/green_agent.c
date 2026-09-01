/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * In-process Green agent payload.
 *
 * Transport + the OFFICIAL frida-gum JS runtime (libgumjs, QuickJS
 * backend).  Scripts are ordinary frida scripts: Interceptor (attach and
 * replace), Memory, Module, Process, Thread, NativeFunction,
 * NativeCallback, rpc.exports, send()/console.* all behave like frida
 * because they ARE frida's own implementation, linked from
 * libfrida-gumjs + libgum + glib/gobject/ffi.
 *
 * Privileged operations (code-page commits) are routed through the
 * root-side server via the broker channel; script messages (send /
 * console) are streamed back to the host over the same channel.
 */
#include "green_agent.h"

#include <gum/gum.h>

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <unistd.h>

#define AGLOG(...) __android_log_print(ANDROID_LOG_INFO, "green-agent", __VA_ARGS__)
#define GREEN_AGENT_MAX_SCRIPT_SIZE (1024U * 1024U)

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
static int green_agent_broker_fd = -1;
static pthread_mutex_t green_agent_broker_lock = PTHREAD_MUTEX_INITIALIZER;

/* Minimal declarations of the gumjs script API (avoiding the gumjs
 * headers' json-glib dependency; everything is an opaque handle). */
typedef struct _GumScript GumScript;
typedef struct _GumScriptBackend GumScriptBackend;
typedef struct _GAsyncResult GAsyncResult;
typedef struct _GCancellable GCancellable;
typedef struct _GError GError;
typedef void (*GumScriptMessageHandler) (GumScript * script,
    const gchar * message, gpointer user_data);
typedef void (*GumScriptBackendCreateSyncFunc) (GumScriptBackend * self,
    const gchar * name, const gchar * source, void * snapshot,
    GCancellable * cancellable, GError ** error);
typedef void (*GumScriptLoadSyncFunc) (GumScript * self,
    GCancellable * cancellable);
typedef void (*GumScriptUnloadSyncFunc) (GumScript * self,
    GCancellable * cancellable);
typedef void (*GumScriptSetMessageHandlerFunc) (GumScript * self,
    GumScriptMessageHandler handler, gpointer data, void * data_destroy);

GumScriptBackend * gum_script_backend_obtain_qjs (void);
GumScript * gum_script_backend_create_sync (GumScriptBackend * self,
    const gchar * name, const gchar * source, void * snapshot,
    GCancellable * cancellable, GError ** error);
void gum_script_set_message_handler (GumScript * self,
    GumScriptMessageHandler handler, gpointer data, void * data_destroy);
void gum_script_load (GumScript * self, GCancellable * cancellable);
void gum_script_load_sync (GumScript * self, GCancellable * cancellable);
void gum_script_unload_sync (GumScript * self, GCancellable * cancellable);

static GumScriptBackend *g_script_backend;
static GumScript *g_script;
static _Atomic int g_loading;

/* ---- broker channel -------------------------------------------------- */

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
        if (n == 0)
            return -1;
        done += (size_t)n;
    }
    return 0;
}

/* One-way message to the attached server (script logs, send(), errors). */
static void green_agent_broker_log(const char *text, size_t len)
{
    struct green_broker_request request;

    pthread_mutex_lock(&green_agent_broker_lock);
    if (green_agent_broker_fd >= 0 && len <= 8192) {
        memset(&request, 0, sizeof(request));
        request.magic = GREEN_AGENT_MAGIC;
        request.command = GREEN_BROKER_LOG;
        request.len = (uint32_t)len;
        if (green_agent_write_full(green_agent_broker_fd, &request,
                                   sizeof(request)) == 0)
            green_agent_write_full(green_agent_broker_fd, text, len);
    }
    pthread_mutex_unlock(&green_agent_broker_lock);
}

/* Forward a privileged operation to the root-side server. */
static int green_agent_broker_request(uint32_t command, uint64_t addr,
                                      uint64_t arg, int64_t *value);
static int green_agent_broker_request_full(uint32_t command, uint64_t addr,
                                           uint64_t arg, const void *payload,
                                           uint32_t len, int64_t *value)
{
    struct green_broker_request request;
    struct green_broker_response response;
    int status;

    pthread_mutex_lock(&green_agent_broker_lock);
    if (green_agent_broker_fd < 0) {
        pthread_mutex_unlock(&green_agent_broker_lock);
        return -ENOENT;
    }
    memset(&request, 0, sizeof(request));
    request.magic = GREEN_AGENT_MAGIC;
    request.command = command;
    request.addr = addr;
    request.arg = arg;
    request.len = len;
    if (green_agent_write_full(green_agent_broker_fd, &request,
                               sizeof(request)) != 0 ||
        (len != 0 &&
            green_agent_write_full(green_agent_broker_fd, payload, len) !=
                0) ||
        green_agent_read_full(green_agent_broker_fd, &response,
                              sizeof(response)) != 0) {
        close(green_agent_broker_fd);
        green_agent_broker_fd = -1;
        pthread_mutex_unlock(&green_agent_broker_lock);
        return -EIO;
    }
    pthread_mutex_unlock(&green_agent_broker_lock);
    status = response.status;
    if (value)
        *value = response.value;
    return status;
}

static int green_agent_broker_request(uint32_t command, uint64_t addr,
                                      uint64_t arg, int64_t *value)
{
    return green_agent_broker_request_full(command, addr, arg, NULL, 0,
                                           value);
}

int green_agent_broker_page_commit(uint64_t page_address, const void *image,
                                   size_t len)
{
    return green_agent_broker_request_full(GREEN_BROKER_PATCH, page_address,
                                           0, image, (uint32_t)len, NULL);
}

/* ---- script runtime (official frida-gum gumjs backend) ---------------- */

static void green_agent_on_message(GumScript * script, const gchar * message,
                                   gpointer user_data)
{
    /* message is JSON: {"type":"log"|"send"|"error","payload":...} */
    __android_log_print(ANDROID_LOG_INFO, "green-debug",
                        "on_message: %.*s", (int) strnlen(message, 120),
                        message);
    green_agent_broker_log(message, strlen(message));
}

/* ---- script runtime (official frida-gum gumjs backend) ---------------- */
/* frida-server 的模式：一个线程跑 default GMainContext 的循环。
 * gumjs 把脚本消息（console/send）作为 idle source 挂在该上下文上，
 * 没有线程迭代它，消息就永远不会派发。 */

static void *
green_main_loop_thread (void *unused)
{
  GMainLoop * loop;

  (void) unused;
  loop = g_main_loop_new (g_main_context_default (), TRUE);
  g_main_loop_run (loop);
  g_main_loop_unref (loop);
  return NULL;
}

/* ---- JS tool ---------------------------------------------------------- */

static void green_agent_js_script_path(char *out, size_t out_size)
{
    char cmdline[128] = {0};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    const char *slash;
    const char *colon;

    if (fd >= 0) {
        ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);
        if (n > 0)
            cmdline[n] = '\0';
    }
    if (cmdline[0] == '\0')
        snprintf(cmdline, sizeof(cmdline), "unknown");

    slash = strrchr(cmdline, '/');
    if (slash) {
        size_t dir_len = (size_t)(slash - cmdline) + 1;
        snprintf(out, out_size, "%.*sgreen_hook.js", (int)dir_len, cmdline);
    } else {
        /* App services use "package:process" as cmdline but share the base
         * package's data directory. */
        colon = strchr(cmdline, ':');
        snprintf(out, out_size, "/data/user/0/%.*s/cache/green_hook.js",
                 colon ? (int)(colon - cmdline) : (int)strlen(cmdline),
                 cmdline);
    }
}

static int green_agent_js_load(const struct green_agent_request *request,
                               struct green_agent_response *response)
{
    char path[256];
    int fd;
    size_t done;
    size_t source_len;
    struct stat script_stat;
    char *source;
    GumScript *script = NULL;
    GError *error = NULL;

    (void)request;
    green_agent_js_script_path(path, sizeof(path));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        snprintf(response->message, sizeof(response->message),
                 "script not found: %s", path);
        return -ENOENT;
    }
    if (fstat(fd, &script_stat) != 0 || script_stat.st_size < 0 ||
        (uint64_t)script_stat.st_size > GREEN_AGENT_MAX_SCRIPT_SIZE) {
        close(fd);
        snprintf(response->message, sizeof(response->message),
                 "invalid script size");
        return -EFBIG;
    }
    source_len = (size_t)script_stat.st_size;
    source = malloc(source_len + 1);
    if (!source) {
        close(fd);
        return -ENOMEM;
    }
    done = 0;
    while (done < source_len) {
        ssize_t n = read(fd, source + done, source_len - done);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    close(fd);
    if (done != source_len) {
        free(source);
        snprintf(response->message, sizeof(response->message),
                 "script read failed");
        return -EIO;
    }
    source[source_len] = '\0';

    if (g_script != NULL) {
        gum_script_unload_sync(g_script, NULL);
        g_object_unref(g_script);
        g_script = NULL;
    }

    script = gum_script_backend_create_sync(g_script_backend, "green",
                                            source, NULL, NULL, &error);
    free(source);
    if (script == NULL) {
        snprintf(response->message, sizeof(response->message), "%s",
                 error ? error->message : "script creation failed");
        if (error)
            g_error_free(error);
        return -EIO;
    }
    g_script = script;

    gum_script_load_sync(script, NULL);

    snprintf(response->message, sizeof(response->message),
             "script loaded from %s", path);
    return 0;
}


static int green_agent_js_eval(const struct green_agent_request *request,
                               struct green_agent_response *response)
{
    char eval_path[300];
    char *slash;
    int fd;
    struct stat st;
    size_t done = 0;
    size_t code_len;
    char *code;
    char *wrapped;
    size_t wrapped_len;
    GumScript *script = NULL;
    GError *error = NULL;

    (void)request;
    green_agent_js_script_path(eval_path, sizeof(eval_path));
    slash = strrchr(eval_path, '/');
    snprintf(slash + 1, sizeof(eval_path) - (slash + 1 - eval_path),
             "green_eval.js");

    fd = open(eval_path, O_RDONLY);
    if (fd < 0) {
        snprintf(response->message, sizeof(response->message),
                 "eval script not found");
        return -ENOENT;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        st.st_size > (off_t)GREEN_AGENT_MAX_SCRIPT_SIZE) {
        close(fd);
        snprintf(response->message, sizeof(response->message),
                 "invalid eval size");
        return -EFBIG;
    }
    code_len = (size_t)st.st_size;
    code = malloc(code_len + 1);
    if (!code) {
        close(fd);
        return -ENOMEM;
    }
    done = 0;
    while (done < code_len) {
        ssize_t n = read(fd, code + done, code_len - done);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    close(fd);
    if (done != code_len) {
        free(code);
        snprintf(response->message, sizeof(response->message),
                 "eval read failed");
        return -EIO;
    }
    code[done] = '\0';

    wrapped_len = code_len + 96;
    wrapped = malloc(wrapped_len);
    if (!wrapped) {
        free(code);
        return -ENOMEM;
    }
    snprintf(wrapped, wrapped_len,
             "send(String((function(){ %s })()));", code);

    if (g_script != NULL) {
        /* 已有脚本时复用其 runtime：卸载旧 eval 脚本不需要。 */
    }

    script = gum_script_backend_create_sync(g_script_backend, "green-eval",
                                            wrapped, NULL, NULL, &error);
    free(wrapped);
    free(code);
    if (script == NULL) {
        snprintf(response->message, sizeof(response->message), "%s",
                 error ? error->message : "eval creation failed");
        if (error)
            g_error_free(error);
        return -EIO;
    }
    gum_script_load_sync(script, NULL);
    g_object_unref(script);

    snprintf(response->message, sizeof(response->message), "eval ok");
    return 0;
}


static int green_agent_js_tool_handler(const struct green_agent_request *request,
                                       struct green_agent_response *response,
                                       void *userdata)
{
    (void)userdata;

    if (request->command == GREEN_AGENT_CMD_JS_LOAD)
        return green_agent_js_load(request, response);
    if (request->command == GREEN_AGENT_CMD_JS_EVAL)
        return green_agent_js_eval(request, response);
    return -EOPNOTSUPP;
}

static const struct green_agent_tool green_agent_js_tool = {
    .id = GREEN_AGENT_TOOL_JS,
    .name = "js",
    .handler = green_agent_js_tool_handler,
};

/* ---- transport -------------------------------------------------------- */

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

static int green_agent_hook_handler(const struct green_agent_request *request,
                                    struct green_agent_response *response,
                                    void *userdata)
{
    int64_t value = 0;
    int status;

    (void)userdata;
    switch (request->command) {
    case GREEN_AGENT_HOOK_REDIRECT:
        if ((request->arg0 & 3) != 0 || (request->arg1 & 3) != 0)
            return -EINVAL;
        status = green_agent_broker_request(GREEN_BROKER_PATCH, request->arg0,
                                            request->arg1, NULL);
        if (status != 0)
            return status;
        response->value = request->arg0;
        return 0;

    case GREEN_AGENT_HOOK_RELEASE:
        status = green_agent_broker_request(GREEN_BROKER_RELEASE,
                                            request->arg0 & ~4095ULL, 0,
                                            &value);
        if (status != 0)
            return status;
        response->value = request->arg0 & ~4095ULL;
        return 0;

    default:
        return -EOPNOTSUPP;
    }
}

static const struct green_agent_tool green_agent_hook_tool = {
    .id = GREEN_AGENT_TOOL_GREEN_HOOK,
    .name = "green_hook",
    .handler = green_agent_hook_handler,
};

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

    if (request->tool == GREEN_AGENT_TOOL_CORE) {
        if (request->command == GREEN_AGENT_CMD_BROKER_ATTACH) {
            int dupfd;

            if (green_agent_peer_uid(fd, &uid) != 0 || uid != 0)
                return -EPERM;
            dupfd = dup(fd);
            if (dupfd < 0)
                return -EIO;
            pthread_mutex_lock(&green_agent_broker_lock);
            if (green_agent_broker_fd >= 0)
                close(green_agent_broker_fd);
            green_agent_broker_fd = dupfd;
            pthread_mutex_unlock(&green_agent_broker_lock);
            snprintf(response->message, sizeof(response->message),
                     "broker attached pid=%d", (int)getpid());
            return 0;
        }
        if (request->command == GREEN_AGENT_CMD_PING) {
            response->value = (uint64_t)getpid();
            snprintf(response->message, sizeof(response->message),
                     "green-agent ready pid=%d", (int)getpid());
            return 0;
        }
        return -EOPNOTSUPP;
    }

    if (green_agent_peer_uid(fd, &uid) != 0 || uid != 0)
        return -EPERM;

    pthread_mutex_lock(&green_agent_registry.lock);
    for (i = 0; i < green_agent_registry.count; i++) {
        if (green_agent_registry.tools[i].id != request->tool)
            continue;
        green_agent_tool_handler handler = green_agent_registry.tools[i].handler;
        void *userdata = green_agent_registry.tools[i].userdata;
        pthread_mutex_unlock(&green_agent_registry.lock);
        return handler(request, response, userdata);
    }
    pthread_mutex_unlock(&green_agent_registry.lock);
    return -ENOENT;
}

static void green_agent_response_init(struct green_agent_response *response)
{
    memset(response, 0, sizeof(*response));
    response->magic = GREEN_AGENT_MAGIC;
    response->version = GREEN_AGENT_VERSION;
    response->size = sizeof(*response);
}

static void *green_agent_handle_client(void *arg);

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
        pthread_t thread;
        int *fdp;

        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        fdp = malloc(sizeof(*fdp));
        if (!fdp) {
            close(client);
            continue;
        }
        *fdp = client;
        if (pthread_create(&thread, NULL, green_agent_handle_client, fdp) == 0)
            pthread_detach(thread);
        else
            close(client);
    }
    return NULL;
}

static void *green_agent_handle_client(void *arg)
{
    int client = *(int *)arg;
    free(arg);

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
        if (request.tool == GREEN_AGENT_TOOL_CORE &&
            request.command == GREEN_AGENT_CMD_BROKER_ATTACH) {
            close(client);
            return NULL;
        }
    }
    close(client);
    return NULL;
}

static void green_agent_start_once(void)
{
    pthread_t thread;
    struct sigaction ignored;

    /* frida's glib fork has no auto-init constructor: the embedder must
     * call glib_init() explicitly.  gumjs attaches script-message sources
     * to the default main context, so a dedicated thread iterates it. */
    extern void glib_init (void);
    glib_init ();
    gum_init_embedded ();
    g_script_backend = gum_script_backend_obtain_qjs ();
    {
        pthread_t loop_thread;

        pthread_create(&loop_thread, NULL, green_main_loop_thread, NULL);
        pthread_detach(loop_thread);
    }
    green_agent_register_tool(&green_agent_hook_tool);
    green_agent_register_tool(&green_agent_js_tool);
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
