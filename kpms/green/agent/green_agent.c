/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * In-process Green agent.
 *
 * This is the payload loaded into a target process.  It contains transport,
 * dispatch, and the built-in QuickJS bridge; privileged Green hook operations
 * stay in the root controller.  New tools can register another handler through
 * the small registry instead of growing the injector protocol.
 */
#include "green_agent.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <android/log.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <unistd.h>

#include <quickjs.h>

#define AGLOG(...) __android_log_print(ANDROID_LOG_INFO, "green-agent", __VA_ARGS__)
#define GREEN_AGENT_MAX_SCRIPT_SIZE (1024U * 1024U)

struct green_agent_registry {
    pthread_mutex_t lock;
    struct green_agent_tool tools[GREEN_AGENT_MAX_TOOLS];
    size_t count;
};

/* ---- JS runtime bridge (QuickJS) ------------------------------------
 * Scripts live at <app cache>/green_hook.js and are pushed by the root
 * controller.  A script calls the native global `hook(target, fn)` which
 * registers `fn` and asks the root broker to redirect `target` to
 * green_agent_js_trampoline; every call of the hooked function then runs
 * the JS callback with an array containing x0-x7 and uses its return value
 * as the function result.
 * ------------------------------------------------------------------ */

static JSRuntime *g_js_rt;
static JSContext *g_js_ctx;
static pthread_mutex_t g_js_lock = PTHREAD_MUTEX_INITIALIZER;
static JSValue g_js_fn;
static int g_js_ready;
static int green_agent_test_target(int value);
static int green_agent_broker_request_full(uint32_t command, uint64_t addr,
                                           uint64_t arg, const void *payload,
                                           uint32_t len, int64_t *value);
static void green_agent_broker_log(const char *text, size_t len);

/* Frida-style API layer, evaluated once before any user script.  Native
 * primitives (__green_*) are registered in js_ensure_runtime(). */
static const char kGreenPrelude[] =
    "var Process = {\n"
    "    id: __green_pid(),\n"
    "    arch: 'arm64',\n"
    "    platform: 'linux',\n"
    "    pageSize: 4096,\n"
    "    enumerateModulesSync: __green_modules\n"
    "};\n"
    "var Module = {\n"
    "    enumerateModulesSync: __green_modules,\n"
    "    getBaseAddress: function (name) {\n"
    "        var ms = __green_modules();\n"
    "        for (var i = 0; i < ms.length; i++)\n"
    "            if (ms[i].name === name || ms[i].path === name)\n"
    "                return ms[i].base;\n"
    "        throw new Error('Module not found: ' + name);\n"
    "    },\n"
    "    findBaseAddress: function (name) {\n"
    "        try { return Module.getBaseAddress(name); }\n"
    "        catch (e) { return null; }\n"
    "    }\n"
    "};\n"
    "var Interceptor = {\n"
    "    replace: function (target, replacement) { hook(target, replacement); },\n"
    "    revert: function (target) { unhook(target); },\n"
    "    flush: function () {},\n"
    "    attach: function () {\n"
    "        throw new Error('Interceptor.attach is not supported yet; '\n"
    "            + 'use Interceptor.replace(target, function(args){ ... })');\n"
    "    }\n"
    "};\n"
    "var console = {\n"
    "    log: function () { log(Array.prototype.join.call(arguments, ' ')); },\n"
    "    info: function () { log(Array.prototype.join.call(arguments, ' ')); },\n"
    "    warn: function () { log(Array.prototype.join.call(arguments, ' ')); },\n"
    "    error: function () { log(Array.prototype.join.call(arguments, ' ')); }\n"
    "};\n"
    "var Memory = {\n"
    "    readUtf8String: function (addr, len) { return __green_read_utf8(addr, len); },\n"
    "    readCString: function (addr, len) { return __green_read_utf8(addr, len); },\n"
    "    readByteArray: function (addr, len) { return __green_mem_read(addr, len); }\n"
    "};\n"
    "function send(message) {\n"
    "    __green_send(typeof message === 'string' ? message : JSON.stringify(message));\n"
    "}\n";

/* The shadow redirect lands here.  Runs the registered JS callback with the
 * live register arguments (x0-x7) and returns its result to the caller. */
__attribute__((noinline)) int64_t green_agent_js_trampoline(
    int64_t a0, int64_t a1, int64_t a2, int64_t a3,
    int64_t a4, int64_t a5, int64_t a6, int64_t a7)
{
    int64_t out = 0;
    int64_t vals[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
    JSValue args;
    JSValue argv[1];
    JSValue rv;

    pthread_mutex_lock(&g_js_lock);
    if (!g_js_ready) {
        pthread_mutex_unlock(&g_js_lock);
        return 0;
    }
    /* QuickJS records a native stack limit.  Hooks may run on a different
     * target thread than the one that loaded the script, so refresh it before
     * entering the runtime. */
    JS_UpdateStackTop(g_js_rt);
    args = JS_NewArray(g_js_ctx);
    for (int i = 0; i < 8; i++)
        JS_SetPropertyUint32(g_js_ctx, args, (uint32_t)i,
                             JS_NewInt64(g_js_ctx, vals[i]));
    argv[0] = args;
    rv = JS_Call(g_js_ctx, g_js_fn, JS_UNDEFINED, 1, argv);
    if (JS_IsException(rv)) {
        JSValue exc = JS_GetException(g_js_ctx);
        const char *msg = JS_ToCString(g_js_ctx, exc);
        __android_log_print(ANDROID_LOG_ERROR, "green-agent",
                            "js hook error: %s", msg ? msg : "?");
        if (msg)
            JS_FreeCString(g_js_ctx, msg);
        JS_FreeValue(g_js_ctx, exc);
    } else {
        int64_t v = 0;
        JS_ToInt64(g_js_ctx, &v, rv);
        out = v;
    }
    JS_FreeValue(g_js_ctx, rv);
    JS_FreeValue(g_js_ctx, args);
    pthread_mutex_unlock(&g_js_lock);
    return out;
}

static JSValue js_native_log(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv)
{
    char line[1024];
    size_t used = 0;

    (void)this_val;
    for (int i = 0; i < argc; i++) {
        const char *s = JS_ToCString(ctx, argv[i]);

        if (!s)
            continue;
        if (used && used < sizeof(line) - 2)
            line[used++] = ' ';
        used += (size_t)snprintf(line + used, sizeof(line) - used, "%s", s);
        if (used >= sizeof(line) - 1)
            used = sizeof(line) - 1;
        JS_FreeCString(ctx, s);
    }
    __android_log_print(ANDROID_LOG_INFO, "green-js", "%s", line);
    green_agent_broker_log(line, used);
    return JS_UNDEFINED;
}

static JSValue js_native_selftest_target(JSContext *ctx,
                                         JSValueConst this_val,
                                         int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    (void)argv;
    return JS_NewInt64(ctx, (int64_t)(uintptr_t)green_agent_test_target);
}

static JSValue js_native_hook(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    uint64_t target = 0;
    int64_t status;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&target, argv[0]) != 0 ||
        (target & 3) != 0 || !JS_IsFunction(ctx, argv[1]))
        return JS_ThrowInternalError(ctx, "hook(target, fn) expects an aligned address and a function");

    status = green_agent_broker_request_full(GREEN_BROKER_PATCH, target,
        (uint64_t)(uintptr_t)green_agent_js_trampoline, NULL, 0, NULL);
    if (status != 0)
        return JS_ThrowInternalError(ctx, "broker patch failed: %d", (int)status);

    JS_FreeValue(ctx, g_js_fn);
    g_js_fn = JS_DupValue(ctx, argv[1]);
    g_js_ready = 1;
    return JS_NewInt32(ctx, 0);
}

static JSValue js_native_unhook(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    uint64_t target = 0;
    int64_t status;

    (void)this_val;
    if (argc < 1 || JS_ToInt64(ctx, (int64_t *)&target, argv[0]) != 0)
        return JS_ThrowInternalError(ctx, "unhook(target) expects an address");

    status = green_agent_broker_request_full(GREEN_BROKER_RELEASE,
                                             target & ~4095ULL, 0, NULL, 0,
                                             NULL);
    if (status < 0)
        return JS_ThrowInternalError(ctx, "broker release failed: %d",
                                     (int)status);
    return JS_NewInt32(ctx, 0);
}

/* Safe file read; returns null on failure. */
static JSValue js_native_read_file(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    static char buf[256 * 1024];
    const char *path;
    ssize_t n;
    int fd;

    (void)this_val;
    if (argc < 1)
        return JS_NULL;
    path = JS_ToCString(ctx, argv[0]);
    if (!path)
        return JS_NULL;
    fd = open(path, O_RDONLY);
    JS_FreeCString(ctx, path);
    if (fd < 0)
        return JS_NULL;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0)
        return JS_NULL;
    return JS_NewStringLen(ctx, buf, (size_t)n);
}

/* Frida-style module list: file-backed mappings from /proc/self/maps,
 * parsed natively (streamed, deduped by device:inode). */
static JSValue js_native_modules(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
    struct seen_path {
        char path[512];
    };
    static struct seen_path seen[512];
    static int seen_count;
    char line[1024];
    JSValue arr;
    int n = 0;
    FILE *maps;

    (void)this_val;
    (void)argc;
    (void)argv;
    maps = fopen("/proc/self/maps", "re");
    if (!maps)
        return JS_NewArray(ctx);
    arr = JS_NewArray(ctx);
    seen_count = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start, end, offset, inode;
        unsigned int devmaj, devmin;
        char perms[8];
        char path[512] = {0};
        char name[512];
        const char *slash;
        JSValue obj;
        int consumed = 0;
        int dup = 0;
        int i;

        if (sscanf(line, "%llx-%llx %7s %llx %x:%x %llu %n\n", &start, &end,
                   perms, &offset, &devmaj, &devmin, &inode, &consumed) < 7)
            continue;
        {
            const char *p = line + consumed;

            while (*p == ' ' || *p == '\t')
                p++;
            snprintf(path, sizeof(path), "%s", p);
        }
        path[strcspn(path, "\n")] = '\0';
        if (path[0] != '/')
            continue; /* anon / [stack] / [heap] */
        for (i = 0; i < seen_count; i++) {
            if (strcmp(seen[i].path, path) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (seen_count < (int)(sizeof(seen) / sizeof(seen[0])))
            snprintf(seen[seen_count++].path, sizeof(seen[0].path), "%s",
                     path);

        slash = strrchr(path, '/');
        snprintf(name, sizeof(name), "%s", slash ? slash + 1 : path);

        obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, name));
        JS_SetPropertyStr(ctx, obj, "base", JS_NewInt64(ctx, (int64_t)start));
        JS_SetPropertyStr(ctx, obj, "size",
                          JS_NewInt64(ctx, (int64_t)(end - start)));
        JS_SetPropertyStr(ctx, obj, "path", JS_NewString(ctx, path));
        JS_SetPropertyStr(ctx, obj, "protection", JS_NewString(ctx, perms));
        JS_SetPropertyUint32(ctx, arr, (uint32_t)n++, obj);
    }
    fclose(maps);
    return arr;
}

static JSValue js_native_pid(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    (void)argv;
    return JS_NewInt32(ctx, (int32_t)getpid());
}

/* send() to the host CLI over the log channel. */
static JSValue js_native_send(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    const char *s;

    (void)this_val;
    if (argc < 1)
        return JS_UNDEFINED;
    s = JS_ToCString(ctx, argv[0]);
    if (!s)
        return JS_UNDEFINED;
    green_agent_broker_log(s, strlen(s));
    JS_FreeCString(ctx, s);
    return JS_UNDEFINED;
}

/* Safe arbitrary reads through /proc/self/mem (no SIGSEGV on unmapped). */
static JSValue js_native_mem_read(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    static uint8_t membuf[65536];
    static int mem_fd = -1;
    uint64_t address = 0;
    int64_t length = 0;
    ssize_t n;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&address, argv[0]) != 0 ||
        JS_ToInt64(ctx, &length, argv[1]) != 0 || length <= 0 ||
        length > (int64_t)sizeof(membuf))
        return JS_NULL;
    if (mem_fd < 0)
        mem_fd = open("/proc/self/mem", O_RDONLY);
    if (mem_fd < 0)
        return JS_NULL;
    n = pread(mem_fd, membuf, (size_t)length, (off_t)address);
    if (n <= 0)
        return JS_NULL;
    return JS_NewArrayBufferCopy(ctx, membuf, (size_t)n);
}

static JSValue js_native_read_utf8(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    static char strbuf[4096];
    static int str_fd = -1;
    uint64_t address = 0;
    int64_t length = (int64_t)sizeof(strbuf) - 1;
    ssize_t n;

    (void)this_val;
    if (argc < 1 || JS_ToInt64(ctx, (int64_t *)&address, argv[0]) != 0)
        return JS_NULL;
    if (argc >= 2 &&
        (JS_ToInt64(ctx, &length, argv[1]) != 0 || length <= 0))
        return JS_NULL;
    if (length > (int64_t)sizeof(strbuf) - 1)
        length = (int64_t)sizeof(strbuf) - 1;
    if (str_fd < 0)
        str_fd = open("/proc/self/mem", O_RDONLY);
    if (str_fd < 0)
        return JS_NULL;
    n = pread(str_fd, strbuf, (size_t)length, (off_t)address);
    if (n <= 0)
        return JS_NULL;
    return JS_NewStringLen(ctx, strbuf, (size_t)n);
}

static int js_ensure_runtime(char *err, size_t errlen)
{
    pthread_mutex_lock(&g_js_lock);
    if (!g_js_rt) {
        g_js_rt = JS_NewRuntime();
        if (!g_js_rt) {
            pthread_mutex_unlock(&g_js_lock);
            snprintf(err, errlen, "JS_NewRuntime failed");
            return -1;
        }
        g_js_ctx = JS_NewContext(g_js_rt);
        if (!g_js_ctx) {
            JS_FreeRuntime(g_js_rt);
            g_js_rt = NULL;
            pthread_mutex_unlock(&g_js_lock);
            snprintf(err, errlen, "JS_NewContext failed");
            return -1;
        }
        {
            JSValue global = JS_GetGlobalObject(g_js_ctx);
            JS_SetPropertyStr(g_js_ctx, global, "hook",
                JS_NewCFunction(g_js_ctx, js_native_hook, "hook", 2));
            JS_SetPropertyStr(g_js_ctx, global, "unhook",
                JS_NewCFunction(g_js_ctx, js_native_unhook, "unhook", 1));
            JS_SetPropertyStr(g_js_ctx, global, "log",
                JS_NewCFunction(g_js_ctx, js_native_log, "log", 1));
            JS_SetPropertyStr(g_js_ctx, global, "selfTestTarget",
                JS_NewCFunction(g_js_ctx, js_native_selftest_target,
                                "selfTestTarget", 0));
            JS_SetPropertyStr(g_js_ctx, global, "__green_pid",
                JS_NewCFunction(g_js_ctx, js_native_pid, "__green_pid", 0));
            JS_SetPropertyStr(g_js_ctx, global, "__green_read_file",
                JS_NewCFunction(g_js_ctx, js_native_read_file,
                                "__green_read_file", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_modules",
                JS_NewCFunction(g_js_ctx, js_native_modules,
                                "__green_modules", 0));
            JS_SetPropertyStr(g_js_ctx, global, "__green_send",
                JS_NewCFunction(g_js_ctx, js_native_send, "__green_send", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_mem_read",
                JS_NewCFunction(g_js_ctx, js_native_mem_read,
                                "__green_mem_read", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_read_utf8",
                JS_NewCFunction(g_js_ctx, js_native_read_utf8,
                                "__green_read_utf8", 2));
            JS_FreeValue(g_js_ctx, global);
        }
        g_js_fn = JS_UNDEFINED;
        g_js_ready = 0;

        /* Frida-style API layer, global scope (user scripts run in an IIFE). */
        {
            JSValue rv = JS_Eval(g_js_ctx, kGreenPrelude, strlen(kGreenPrelude),
                                 "<green-prelude>", JS_EVAL_TYPE_GLOBAL);
            if (JS_IsException(rv)) {
                JSValue exc = JS_GetException(g_js_ctx);
                const char *msg = JS_ToCString(g_js_ctx, exc);
                snprintf(err, errlen, "prelude error: %s", msg ? msg : "?");
                if (msg)
                    JS_FreeCString(g_js_ctx, msg);
                JS_FreeValue(g_js_ctx, exc);
                pthread_mutex_unlock(&g_js_lock);
                return -1;
            }
            JS_FreeValue(g_js_ctx, rv);
        }
    }
    pthread_mutex_unlock(&g_js_lock);
    return 0;
}

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

static int green_agent_js_tool_handler(const struct green_agent_request *request,
                                       struct green_agent_response *response,
                                       void *userdata)
{
    char path[256];
    char err[192] = {0};
    int fd;
    ssize_t n;
    size_t done;
    size_t source_len;
    struct stat script_stat;
    char *source;
    char *wrapped;
    JSValue rv;

    (void)userdata;
    green_agent_js_script_path(path, sizeof(path));

    if (request->command == GREEN_AGENT_CMD_JS_LOAD) {
        if (js_ensure_runtime(err, sizeof(err)) != 0) {
            snprintf(response->message, sizeof(response->message), "%s", err);
            return -EIO;
        }

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
            n = read(fd, source + done, source_len - done);
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

        /* Wrap in an IIFE: repeated loads get a fresh variable scope. */
        wrapped = malloc(source_len + 32);
        if (!wrapped) {
            free(source);
            return -ENOMEM;
        }
        snprintf(wrapped, source_len + 32, "(function(){\n%.*s\n})()",
                 (int)source_len, source);

        pthread_mutex_lock(&g_js_lock);
        JS_UpdateStackTop(g_js_rt);
        rv = JS_Eval(g_js_ctx, wrapped, strlen(wrapped), "green_hook.js",
                     JS_EVAL_TYPE_GLOBAL);
        free(wrapped);
        free(source);
        if (JS_IsException(rv)) {
            JSValue exc = JS_GetException(g_js_ctx);
            const char *msg = JS_ToCString(g_js_ctx, exc);
            snprintf(response->message, sizeof(response->message),
                     "script error: %s", msg ? msg : "?");
            if (msg)
                JS_FreeCString(g_js_ctx, msg);
            JS_FreeValue(g_js_ctx, exc);
            pthread_mutex_unlock(&g_js_lock);
            return -EIO;
        }
        JS_FreeValue(g_js_ctx, rv);
        pthread_mutex_unlock(&g_js_lock);

        snprintf(response->message, sizeof(response->message),
                 "script loaded from %s", path);
        return 0;
    }

    if (request->command == GREEN_AGENT_CMD_JS_CALL) {
        /* Indirect call through a volatile function pointer: the compiler
         * must not inline the target, so the call goes through the patched
         * entry and the shadow redirect actually fires. */
        static int (*volatile js_probe)(int) = green_agent_test_target;
        int during = js_probe(1);

        response->value = (uint64_t)during;
        snprintf(response->message, sizeof(response->message),
                 "probe during=%d", during);
        return 0;
    }

    return -EOPNOTSUPP;
}

static const struct green_agent_tool green_agent_js_tool = {
    .id = GREEN_AGENT_TOOL_JS,
    .name = "js",
    .handler = green_agent_js_tool_handler,
};

static struct green_agent_registry green_agent_registry = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};
static pthread_once_t green_agent_once = PTHREAD_ONCE_INIT;
static int green_agent_server_fd = -1;
static int green_agent_broker_fd = -1;
static pthread_mutex_t green_agent_broker_lock = PTHREAD_MUTEX_INITIALIZER;

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

/* Forward a privileged operation to the root-side broker over the
 * connection the broker established.  Returns -ENOENT while no broker is
 * attached. */
/* One-way script log line to the attached server (best effort). */
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
    return green_agent_broker_request_full(command, addr, arg, NULL, 0, value);
}

int green_agent_broker_page_commit(uint64_t page_address, const void *image,
                                   size_t len)
{
    return green_agent_broker_request_full(GREEN_BROKER_PATCH, page_address,
                                           0, image, (uint32_t)len, NULL);
}

__attribute__((noinline, aligned(4096))) static int green_agent_test_target(int value)
{
    asm volatile("" ::: "memory");
    return value + 1;
}

__attribute__((noinline, aligned(4096))) static int green_agent_test_replacement(int value)
{
    asm volatile("" ::: "memory");
    return value + 100;
}

static int green_agent_hook_self_test(struct green_agent_response *response)
{
    int64_t value = 0;
    int before;
    int during;
    int status;

    before = green_agent_test_target(1);
    if (before != 2)
        return -EFAULT;

    /* The root-side broker snapshots this page (process_vm_readv), emits the
     * GumArm64Writer redirect and commits it through the shadow ABI. */
    status = green_agent_broker_request(
        GREEN_BROKER_PATCH, (uint64_t)(uintptr_t)green_agent_test_target,
        (uint64_t)(uintptr_t)green_agent_test_replacement, &value);
    if (status != 0)
        return status;

    during = green_agent_test_target(1);
    if (during != 101) {
        green_agent_broker_request(
            GREEN_BROKER_RELEASE,
            (uint64_t)(uintptr_t)green_agent_test_target & ~4095ULL, 0, NULL);
        return -EFAULT;
    }

    status = green_agent_broker_request(
        GREEN_BROKER_RELEASE,
        (uint64_t)(uintptr_t)green_agent_test_target & ~4095ULL, 0, NULL);
    if (status != 0)
        return status;

    response->value = (uint64_t)((before << 16) | during);
    snprintf(response->message, sizeof(response->message),
             "green_hook self-test before=%d during=%d after=%d", before,
             during, green_agent_test_target(1));
    return green_agent_test_target(1) == 2 ? 0 : -EFAULT;
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

static void green_agent_response_init(struct green_agent_response *response)
{
    memset(response, 0, sizeof(*response));
    response->magic = GREEN_AGENT_MAGIC;
    response->version = GREEN_AGENT_VERSION;
    response->size = sizeof(*response);
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
        /* Pure forwarding: the root broker snapshots this process's page
         * via process_vm_readv and emits the GumArm64Writer redirect. */
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

    case GREEN_AGENT_HOOK_SELF_TEST:
        return green_agent_hook_self_test(response);

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

    AGLOG("dispatch fd=%d tool=%u cmd=%u", fd, request->tool,
          request->command);

    if (request->tool == GREEN_AGENT_TOOL_CORE) {
        if (request->command == GREEN_AGENT_CMD_BROKER_ATTACH) {
            /* Only root may become the broker.  dup() the connection so it
             * survives this handler thread exiting; nobody but
             * green_agent_broker_request() ever reads or writes it (two
             * readers would steal each other's bytes). */
            if (green_agent_peer_uid(fd, &uid) != 0 || uid != 0)
                return -EPERM;
            int dupfd = dup(fd);
            if (dupfd < 0)
                return -EIO;
            pthread_mutex_lock(&green_agent_broker_lock);
            if (green_agent_broker_fd >= 0)
                close(green_agent_broker_fd);
            green_agent_broker_fd = dupfd;
            pthread_mutex_unlock(&green_agent_broker_lock);
            AGLOG("attach: peer fd=%d dupfd=%d uid=%d", fd, dupfd, (int)uid);
            snprintf(response->message, sizeof(response->message),
                     "broker attached pid=%d", (int)getpid());
            return 0;
        }
        return green_agent_core_dispatch(request, response);
    }

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

/* One thread per connection.  A BROKER_ATTACH connection is kept open: the
 * thread blocks until the root side disconnects (broker channel closed). */
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
            /* The dup'd broker_fd now owns this channel exclusively; any
             * further read here would steal broker responses. */
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
