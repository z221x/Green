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

/* Android 15 MTE: malloc returns tagged pointers (0xb4...).  /proc/self/mem
 * and process_vm_* reject tagged addresses, so strip the top byte in every
 * memory primitive.  In-process dereferences ignore the tag (TBI) anyway. */
#define GREEN_UNTAG(p) ((uint64_t)(p) & 0x00ffffffffffffffULL)

/* Apps (untrusted_app domain) cannot open /proc/self/mem — validate
 * addresses against cached /proc/self/maps and use plain memcpy. */
struct green_range { uint64_t lo, hi; int prot; };
static struct green_range g_maps_ranges[4096];
static int g_maps_count;

static void green_maps_refresh(void)
{
    FILE *f = fopen("/proc/self/maps", "re");
    char line[512];
    int n = 0;

    g_maps_count = 0;
    if (f == NULL)
        return;
    while (fgets(line, sizeof(line), f) != NULL && n < 4096) {
        unsigned long long lo, hi;
        char perms[8];
        if (sscanf(line, "%llx-%llx %4s", &lo, &hi, perms) != 3)
            continue;
        g_maps_ranges[n].lo = lo;
        g_maps_ranges[n].hi = hi;
        g_maps_ranges[n].prot = (perms[0] == 'r' ? 1 : 0) |
                                (perms[1] == 'w' ? 2 : 0) |
                                (perms[2] == 'x' ? 4 : 0);
        n++;
    }
    fclose(f);
    g_maps_count = n;
}

static int green_addr_ok(uint64_t addr, size_t len, int need)
{
    int i;

    if (len == 0 || addr == 0)
        return 0;
    for (i = 0; i < g_maps_count; i++) {
        if (addr >= g_maps_ranges[i].lo &&
            addr + len <= g_maps_ranges[i].hi &&
            (g_maps_ranges[i].prot & need) == need)
            return 1;
    }
    return 0;
}

#define GREEN_PROT_R 1
#define GREEN_PROT_W 2

/* dlopen() handle table: PAC-signed soinfo pointers cannot survive a JS
 * Number round-trip, so scripts only ever see 1-based table IDs. */
#define GREEN_MAX_DLH 64
static void *g_dl_handles[GREEN_MAX_DLH];

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
#include <sys/mman.h>
#include <dlfcn.h>
#include <linux/un.h>
#include <unistd.h>

#include <quickjs.h>
#include <gum/arch-arm64/gumarm64writer.h>
#include <gum/arch-arm64/gumarm64relocator.h>
#include <gum/arch-arm64/gumarm64reader.h>


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

JSRuntime *g_js_rt;
JSContext *g_js_ctx;
/* Recursive: a hook may fire on the same thread while the runtime lock is
 * held (e.g. a NativeFunction call made from a script under evaluation). */
pthread_mutex_t g_js_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static JSValue g_js_fn;
static int g_js_ready;
static int green_agent_test_target(int value);
static int green_agent_broker_request_full(uint32_t command, uint64_t addr,
                                           uint64_t arg, const void *payload,
                                           uint32_t len, int64_t *value);
static void green_agent_broker_log(const char *text, size_t len);
static JSValue js_native_broker_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);

/* Frida-style API layer, evaluated once before any user script.  Native
 * primitives (__green_*) are registered in js_ensure_runtime(). */
#include "prelude.inc"
#include "fjb.inc"

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

static JSValue js_native_interceptor_attach(JSContext *ctx,
    JSValueConst this_val, int argc, JSValueConst *argv);
static JSValue js_native_new_callback(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_mem_write(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);

/* ====================================================================== */
/* frida-java-bridge host compatibility                                   */
/* ====================================================================== */

#include <elf.h>
#include "gumjs/gumcmodule.h"

static void *green_module_dlsym(const char *mod_name, const char *sym_name)
{
    FILE *maps;
    char line[512];
    unsigned long long base = 0;

    maps = fopen("/proc/self/maps", "re");
    if (maps == NULL)
        return NULL;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, mod_name) != NULL) {
            unsigned long long start;
            unsigned long off;
            if (sscanf(line, "%llx-%*llx %*s %lx", &start, &off) == 2 &&
                off == 0) {
                base = start;
                break;
            }
        }
    }
    fclose(maps);
    if (base == 0)
        return NULL;

    {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
        Elf64_Phdr *ph = (Elf64_Phdr *)(base + eh->e_phoff);
        Elf64_Dyn *dyn = NULL;
        Elf64_Sym *symtab = NULL;
        const char *strtab = NULL;
        uint64_t hash = 0, gnu_hash = 0, strsz = 0;
        uint32_t nsyms = 0;
        int i;

        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
            return NULL;
        for (i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_DYNAMIC)
                dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
        if (dyn == NULL)
            return NULL;
        for (; dyn->d_tag != DT_NULL; dyn++) {
            switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr); break;
            case DT_STRTAB: strtab = (const char *)(base + dyn->d_un.d_ptr); break;
            case DT_STRSZ:  strsz = dyn->d_un.d_ptr; break;
            case DT_HASH:   hash = dyn->d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = dyn->d_un.d_ptr; break;
            }
        }
        if (symtab == NULL || strtab == NULL)
            return NULL;
        if (strsz == 0)
            strsz = 0x100000;

        if (hash != 0)
            nsyms = ((uint32_t *)(base + hash))[1];
        else if (gnu_hash != 0)
            nsyms = (uint32_t)((const uint8_t *)strtab
                - (const uint8_t *)symtab) / sizeof(Elf64_Sym);
        if (nsyms == 0 || nsyms > 400000)
            return NULL;
        for (i = 0; i < (int)nsyms; i++) {
            if (symtab[i].st_name == 0 ||
                (uint64_t)symtab[i].st_name >= strsz)
                continue;
            if (strcmp(strtab + symtab[i].st_name, sym_name) == 0 &&
                symtab[i].st_value != 0)
                return (void *)(base + symtab[i].st_value);
        }
    }
    return NULL;
}

/* __green_module_list_imports(moduleName) -> [{name, address}]
 * address is the GOT/PLT slot VA; the runtime has already resolved it. */
static JSValue js_module_list_imports(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv)
{
    const char *mod_name;
    unsigned long long base = 0;
    JSValue arr;
    FILE *maps;
    char line[512];
    Elf64_Ehdr *eh;
    Elf64_Phdr *ph;
    Elf64_Dyn *dyn = NULL;
    Elf64_Rela *rela = NULL, *jmprel = NULL;
    Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    uint64_t strsz = 0, relasz = 0, pltrelsz = 0;
    size_t relaent = sizeof(Elf64_Rela);
    int i, n = 0;

    (void)this_val;
    if (argc < 1)
        return JS_NewArray(ctx);
    mod_name = JS_ToCString(ctx, argv[0]);
    if (mod_name == NULL)
        return JS_NewArray(ctx);

    maps = fopen("/proc/self/maps", "re");
    if (maps != NULL) {
        while (fgets(line, sizeof(line), maps) != NULL) {
            if (strstr(line, mod_name) != NULL) {
                unsigned long long start;
                unsigned long off;
                if (sscanf(line, "%llx-%*llx %*s %lx", &start, &off) == 2 &&
                    off == 0) {
                    base = start;
                    break;
                }
            }
        }
        fclose(maps);
    }
    arr = JS_NewArray(ctx);
    if (base == 0) {
        JS_FreeCString(ctx, mod_name);
        return arr;
    }

    eh = (Elf64_Ehdr *)base;
    ph = (Elf64_Phdr *)(base + eh->e_phoff);
    for (i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_DYNAMIC)
            dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
    if (dyn == NULL) {
        JS_FreeCString(ctx, mod_name);
        return arr;
    }
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_RELA:   rela = (Elf64_Rela *)(base + dyn->d_un.d_ptr); break;
        case DT_RELASZ: relasz = dyn->d_un.d_val; break;
        case DT_JMPREL: jmprel = (Elf64_Rela *)(base + dyn->d_un.d_ptr); break;
        case DT_PLTRELSZ: pltrelsz = dyn->d_un.d_val; break;
        case DT_SYMTAB: symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr); break;
        case DT_STRTAB: strtab = (const char *)(base + dyn->d_un.d_ptr); break;
        case DT_STRSZ:  strsz = dyn->d_un.d_val; break;
        case DT_RELAENT: relaent = (size_t)dyn->d_un.d_val; break;
        }
    }
    if (strtab == NULL || symtab == NULL || strsz == 0) {
        JS_FreeCString(ctx, mod_name);
        return arr;
    }

    for (i = 0; i < 2; i++) {
        Elf64_Rela *r = (i == 0) ? jmprel : rela;
        uint64_t rsz = (i == 0) ? pltrelsz : relasz;
        size_t cnt, k;

        if (r == NULL || rsz == 0)
            continue;
        cnt = rsz / relaent;
        if (cnt > 20000)
            cnt = 20000;
        for (k = 0; k < cnt && n < 20000; k++) {
            uint32_t sym_idx = (uint32_t)(ELF64_R_SYM(r[k].r_info));
            const char *name = (sym_idx != 0 &&
                symtab[sym_idx].st_name < strsz)
                ? strtab + symtab[sym_idx].st_name : NULL;
            if (name == NULL || name[0] == 0)
                continue;
            {
                JSValue o = JS_NewObject(ctx);
                JS_SetPropertyStr(ctx, o, "name", JS_NewString(ctx, name));
                JS_SetPropertyStr(ctx, o, "address",
                    JS_NewInt64(ctx, (int64_t)(base + r[k].r_offset)));
                JS_SetPropertyUint32(ctx, arr, (uint32_t)n++, o);
            }
        }
    }
    JS_FreeCString(ctx, mod_name);
    return arr;
}

static JSValue js_find_export_any(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    static const char *candidates[] = {
        "libart.so", "libnativehelper.so", "libandroid_runtime.so",
        "libartbase.so", "libc.so", NULL,
    };
    const char *name;
    void *sym = NULL;
    int i;

    (void)this_val;
    if (argc < 1)
        return JS_NULL;
    name = JS_ToCString(ctx, argv[0]);
    if (name == NULL)
        return JS_NULL;
    sym = dlsym(RTLD_DEFAULT, name);
    for (i = 0; sym == NULL && candidates[i] != NULL; i++)
        sym = green_module_dlsym(candidates[i], name);
    JS_FreeCString(ctx, name);
    return sym ? JS_NewInt64(ctx, (int64_t)(uintptr_t)sym) : JS_NULL;
}

static JSValue js_icache_flush(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
    uint64_t address = 0;
    int64_t length = 0;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&address, argv[0]) != 0 ||
        JS_ToInt64(ctx, &length, argv[1]) != 0)
        return JS_FALSE;
    address = GREEN_UNTAG(address);
    __builtin___clear_cache((char *)(uintptr_t)address,
                            (char *)(uintptr_t)(address + (uint64_t)length));
    return JS_TRUE;
}

static JSValue js_native_getuid(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    (void)this_val; (void)argc; (void)argv;
    return JS_NewInt64(ctx, (int64_t)getuid());
}

static JSValue js_module_list_syms(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    const char *mod_name, *mod_path = NULL;
    int dynsym_only = 0;
    unsigned long long base = 0;
    JSValue arr;
    FILE *maps, *f = NULL;
    char line[512];

    (void)this_val;
    if (argc < 1)
        return JS_NewArray(ctx);
    mod_name = JS_ToCString(ctx, argv[0]);
    if (mod_name == NULL)
        return JS_NewArray(ctx);
    if (argc >= 2)
        JS_ToInt32(ctx, &dynsym_only, argv[1]);

    maps = fopen("/proc/self/maps", "re");
    if (maps != NULL) {
        while (fgets(line, sizeof(line), maps) != NULL) {
            if (strstr(line, mod_name) != NULL) {
                unsigned long long start;
                unsigned long off;
                char path[512] = {0};
                if (sscanf(line, "%llx-%*llx %*s %lx %*x:%*x %*llu %511s",
                           &start, &off, path) >= 2) {
                    if (off == 0 && base == 0)
                        base = start;
                    if (path[0] == '/' && mod_path == NULL)
                        mod_path = strdup(path);
                }
            }
        }
        fclose(maps);
    }
    arr = JS_NewArray(ctx);
    if (base == 0) {
        JS_FreeCString(ctx, mod_name);
        return arr;
    }

    if (dynsym_only) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
        Elf64_Phdr *ph = (Elf64_Phdr *)(base + eh->e_phoff);
        Elf64_Dyn *dyn = NULL;
        Elf64_Sym *symtab = NULL;
        const char *strtab = NULL;
        uint64_t hash = 0, gnu_hash = 0, strsz = 0;
        uint32_t nsyms = 0;
        int i, n = 0;

        for (i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_DYNAMIC)
                dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
        if (dyn != NULL) {
            for (; dyn->d_tag != DT_NULL; dyn++) {
                switch (dyn->d_tag) {
                case DT_SYMTAB: symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr); break;
                case DT_STRTAB: strtab = (const char *)(base + dyn->d_un.d_ptr); break;
                case DT_STRSZ:  strsz = dyn->d_un.d_ptr; break;
                case DT_HASH:   hash = dyn->d_un.d_ptr; break;
                case DT_GNU_HASH: gnu_hash = dyn->d_un.d_ptr; break;
                }
            }
            if (strsz == 0)
                strsz = 0x400000;
            if (hash != 0)
                nsyms = ((uint32_t *)(base + hash))[1];
            else if (gnu_hash != 0 && strtab != NULL && symtab != NULL)
                nsyms = (uint32_t)((const uint8_t *)strtab
                    - (const uint8_t *)symtab) / sizeof(Elf64_Sym);
            if (nsyms > 200000)
                nsyms = 200000;
            for (i = 0; i < (int)nsyms && n < 200000; i++) {
                if (symtab[i].st_name == 0 || symtab[i].st_value == 0 ||
                    (uint64_t)symtab[i].st_name >= strsz)
                    continue;
                JSValue o = JS_NewObject(ctx);
                JS_SetPropertyStr(ctx, o, "name",
                    JS_NewString(ctx, strtab + symtab[i].st_name));
                JS_SetPropertyStr(ctx, o, "address",
                    JS_NewInt64(ctx, (int64_t)(base + symtab[i].st_value)));
                JS_SetPropertyUint32(ctx, arr, (uint32_t)n++, o);
            }
        }
    } else if (mod_path != NULL) {
        f = fopen(mod_path, "re");
        if (f != NULL) {
            Elf64_Ehdr eh;
            if (fread(&eh, sizeof(eh), 1, f) == 1 &&
                memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0 &&
                eh.e_shoff != 0) {
                Elf64_Shdr *sh = malloc(eh.e_shentsize * eh.e_shnum);
                if (sh != NULL &&
                    fseek(f, (long)eh.e_shoff, SEEK_SET) == 0 &&
                    fread(sh, eh.e_shentsize, eh.e_shnum, f) == eh.e_shnum) {
                    Elf64_Shdr *symh = NULL, *strh = NULL;
                    int i;
                    for (i = 0; i < eh.e_shnum; i++) {
                        if (sh[i].sh_type == SHT_SYMTAB) {
                            symh = &sh[i];
                            strh = &sh[symh->sh_link];
                            break;
                        }
                    }
                    if (symh != NULL && strh != NULL) {
                        Elf64_Sym *syms = malloc(symh->sh_size);
                        char *strs = malloc(strh->sh_size);
                        int n = 0;
                        if (syms != NULL && strs != NULL &&
                            fseek(f, (long)symh->sh_offset, SEEK_SET) == 0 &&
                            fread(syms, 1, symh->sh_size, f) == symh->sh_size &&
                            fseek(f, (long)strh->sh_offset, SEEK_SET) == 0 &&
                            fread(strs, 1, strh->sh_size, f) == strh->sh_size) {
                            size_t cnt = symh->sh_size / sizeof(Elf64_Sym);
                            for (i = 0; i < (int)cnt && n < 200000; i++) {
                                if (syms[i].st_name == 0 ||
                                    syms[i].st_name >= strh->sh_size ||
                                    syms[i].st_value == 0 ||
                                    ELF64_ST_TYPE(syms[i].st_info) ==
                                        STT_FILE)
                                    continue;
                                JSValue o = JS_NewObject(ctx);
                                JS_SetPropertyStr(ctx, o, "name",
                                    JS_NewString(ctx, strs + syms[i].st_name));
                                JS_SetPropertyStr(ctx, o, "address",
                                    JS_NewInt64(ctx,
                                        (int64_t)(base + syms[i].st_value)));
                                JS_SetPropertyUint32(ctx, arr,
                                    (uint32_t)n++, o);
                            }
                        }
                        free(syms);
                        free(strs);
                    }
                }
                free(sh);
            }
            fclose(f);
        }
    }
    free(mod_path);
    JS_FreeCString(ctx, mod_name);
    return arr;
}

#define GREEN_MAX_CMOD 8
static GumCModule *g_cmods[GREEN_MAX_CMOD];

static JSValue js_cmodule_new(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    const char *source;
    GError *err = NULL;
    GumCModule *cm;
    int i, slot = -1;

    (void)this_val;
    if (argc < 1 || !JS_IsString(argv[0]))
        return JS_ThrowInternalError(ctx, "CModule(source, symbols)");
    for (i = 0; i < GREEN_MAX_CMOD; i++)
        if (g_cmods[i] == NULL) { slot = i; break; }
    if (slot < 0)
        return JS_ThrowInternalError(ctx, "too many CModules");
    source = JS_ToCString(ctx, argv[0]);
    if (source == NULL)
        return JS_EXCEPTION;
    {
        /* gum dereferences options unconditionally — pass ANY toolchain */
        GumCModuleOptions opts;
        opts.toolchain = GUM_CMODULE_TOOLCHAIN_ANY;
        cm = gum_cmodule_new(source, NULL, &opts, &err);
    }
    JS_FreeCString(ctx, source);
    if (cm == NULL) {
        JSValue e = JS_ThrowInternalError(ctx, "CModule compile: %s",
            err && err->message ? err->message : "?");
        if (err)
            g_error_free(err);
        return e;
    }
    g_cmods[slot] = cm;
    return JS_NewInt32(ctx, slot);
}

static GumCModule *cmod_get(int h)
{
    return (h >= 0 && h < GREEN_MAX_CMOD) ? g_cmods[h] : NULL;
}

static JSValue js_cmodule_add_symbol(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv)
{
    int h = -1;
    const char *name;
    int64_t value = 0;
    GumCModule *cm;

    (void)this_val;
    if (argc < 3 || JS_ToInt32(ctx, &h, argv[0]) != 0)
        return JS_FALSE;
    cm = cmod_get(h);
    if (cm == NULL)
        return JS_FALSE;
    name = JS_ToCString(ctx, argv[1]);
    if (name == NULL)
        return JS_FALSE;
    JS_ToInt64(ctx, &value, argv[2]);
    gum_cmodule_add_symbol(cm, name, (gconstpointer)(uintptr_t)value);
    JS_FreeCString(ctx, name);
    return JS_TRUE;
}

static JSValue js_cmodule_link(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
    int h = -1;
    GError *err = NULL;
    GumCModule *cm;

    (void)this_val;
    if (argc < 1 || JS_ToInt32(ctx, &h, argv[0]) != 0)
        return JS_FALSE;
    cm = cmod_get(h);
    if (cm == NULL)
        return JS_FALSE;
    if (!gum_cmodule_link(cm, &err)) {
        __android_log_print(ANDROID_LOG_ERROR, "green-agent",
            "CModule link: %s", err && err->message ? err->message : "?");
        if (err)
            g_error_free(err);
        return JS_FALSE;
    }
    return JS_TRUE;
}

static JSValue js_cmodule_get(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    int h = -1;
    const char *name;
    GumCModule *cm;
    void *sym;

    (void)this_val;
    if (argc < 2 || JS_ToInt32(ctx, &h, argv[0]) != 0)
        return JS_NewInt64(ctx, 0);
    cm = cmod_get(h);
    if (cm == NULL)
        return JS_NewInt64(ctx, 0);
    name = JS_ToCString(ctx, argv[1]);
    if (name == NULL)
        return JS_NewInt64(ctx, 0);
    sym = gum_cmodule_find_symbol_by_name(cm, name);
    JS_FreeCString(ctx, name);
    return JS_NewInt64(ctx, (int64_t)(uintptr_t)sym);
}

static JSValue js_a64w_new(JSContext *ctx, JSValueConst this_val,
                           int argc, JSValueConst *argv);
static JSValue js_a64w(JSContext *ctx, JSValueConst this_val, int argc,
                       JSValueConst *argv);

static JSValue js_native_mem_alloc(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_mem_free(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_mprotect(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_call(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_dlopen(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_dlsym(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
/* Safe export lookup: uses dlsym(RTLD_DEFAULT) which searches all
 * loaded modules without needing a dlopen handle. */
static JSValue js_native_find_export_safe(JSContext *ctx,
                                          JSValueConst this_val,
                                          int argc, JSValueConst *argv)
{
    const char *name;
    void *sym;

    (void)this_val;
    if (argc < 1)
        return JS_NULL;
    name = JS_ToCString(ctx, argv[0]);
    if (!name)
        return JS_NULL;
    sym = dlsym(RTLD_DEFAULT, name);
    JS_FreeCString(ctx, name);
    if (!sym)
        return JS_NULL;
    return JS_NewInt64(ctx, (int64_t)(uintptr_t)sym);
}

static JSValue js_native_gettid(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_sleep(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
static JSValue js_native_file_write(JSContext *ctx, JSValueConst this_val,
    int argc, JSValueConst *argv);
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
    address = GREEN_UNTAG(address);
    if (g_maps_count == 0)
        green_maps_refresh();
    if (!green_addr_ok(address, (size_t)length, GREEN_PROT_R)) {
        green_maps_refresh();
        if (!green_addr_ok(address, (size_t)length, GREEN_PROT_R))
            return JS_NULL;
    }
    memcpy(membuf, (const void *)(uintptr_t)address, (size_t)length);
    return JS_NewArrayBufferCopy(ctx, membuf, (size_t)length);
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
    address = GREEN_UNTAG(address);
    if (argc >= 2 &&
        (JS_ToInt64(ctx, &length, argv[1]) != 0 || length <= 0))
        return JS_NULL;
    if (length > (int64_t)sizeof(strbuf) - 1)
        length = (int64_t)sizeof(strbuf) - 1;
    if (g_maps_count == 0)
        green_maps_refresh();
    if (!green_addr_ok(address, 1, GREEN_PROT_R)) {
        green_maps_refresh();
        if (!green_addr_ok(address, 1, GREEN_PROT_R))
            return JS_NULL;
    }
    {
        size_t avail = (size_t)length;
        for (int i = 0; i < g_maps_count; i++) {
            if (address >= g_maps_ranges[i].lo &&
                address < g_maps_ranges[i].hi) {
                uint64_t room = g_maps_ranges[i].hi - address;
                if (room < (uint64_t)avail)
                    avail = (size_t)room;
                break;
            }
        }
        memcpy(strbuf, (const void *)(uintptr_t)address, avail);
        n = (ssize_t)avail;
    }
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
            JS_SetPropertyStr(g_js_ctx, global, "__green_broker_log",
                JS_NewCFunction(g_js_ctx, js_native_broker_log,
                                "__green_broker_log", 1));
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
            JS_SetPropertyStr(g_js_ctx, global, "__green_interceptor_attach",
                JS_NewCFunction(g_js_ctx, js_native_interceptor_attach,
                                "__green_interceptor_attach", 3));
            JS_SetPropertyStr(g_js_ctx, global, "__green_new_callback",
                JS_NewCFunction(g_js_ctx, js_native_new_callback,
                                "__green_new_callback", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_mem_write",
                JS_NewCFunction(g_js_ctx, js_native_mem_write,
                                "__green_mem_write", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_mem_alloc",
                JS_NewCFunction(g_js_ctx, js_native_mem_alloc,
                                "__green_mem_alloc", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_mem_free",
                JS_NewCFunction(g_js_ctx, js_native_mem_free,
                                "__green_mem_free", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_mprotect",
                JS_NewCFunction(g_js_ctx, js_native_mprotect,
                                "__green_mprotect", 3));
            JS_SetPropertyStr(g_js_ctx, global, "__green_native_call",
                JS_NewCFunction(g_js_ctx, js_native_call,
                                "__green_native_call", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_dlopen",
                JS_NewCFunction(g_js_ctx, js_native_dlopen,
                                "__green_dlopen", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_dlsym",
                JS_NewCFunction(g_js_ctx, js_native_dlsym,
                                "__green_dlsym", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_find_export_safe",
                JS_NewCFunction(g_js_ctx, js_native_find_export_safe,
                                "__green_find_export_safe", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_gettid",
                JS_NewCFunction(g_js_ctx, js_native_gettid,
                                "__green_gettid", 0));
            JS_SetPropertyStr(g_js_ctx, global, "__green_sleep",
                JS_NewCFunction(g_js_ctx, js_native_sleep,
                                "__green_sleep", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_file_write",
                JS_NewCFunction(g_js_ctx, js_native_file_write,
                                "__green_file_write", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_find_export_any",
                JS_NewCFunction(g_js_ctx, js_find_export_any,
                                "__green_find_export_any", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_icache_flush",
                JS_NewCFunction(g_js_ctx, js_icache_flush,
                                "__green_icache_flush", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_getuid",
                JS_NewCFunction(g_js_ctx, js_native_getuid,
                                "__green_getuid", 0));
            JS_SetPropertyStr(g_js_ctx, global, "__green_module_list_imports",
                JS_NewCFunction(g_js_ctx, js_module_list_imports,
                                "__green_module_list_imports", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_module_list_syms",
                JS_NewCFunction(g_js_ctx, js_module_list_syms,
                                "__green_module_list_syms", 2));
            JS_SetPropertyStr(g_js_ctx, global, "__green_cmodule_new",
                JS_NewCFunction(g_js_ctx, js_cmodule_new,
                                "__green_cmodule_new", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_cmodule_add_symbol",
                JS_NewCFunction(g_js_ctx, js_cmodule_add_symbol,
                                "__green_cmodule_add_symbol", 3));
            JS_SetPropertyStr(g_js_ctx, global, "__green_cmodule_link",
                JS_NewCFunction(g_js_ctx, js_cmodule_link,
                                "__green_cmodule_link", 1));
            JS_SetPropertyStr(g_js_ctx, global, "__green_cmodule_get",
                JS_NewCFunction(g_js_ctx, js_cmodule_get,
                                "__green_cmodule_get", 2));
            {
                extern void green_writer_register_natives(JSContext *,
                                                          JSValue);
                extern void green_insn_register_natives(JSContext *,
                                                        JSValue);
                green_writer_register_natives(g_js_ctx, global);
                green_insn_register_natives(g_js_ctx, global);
            }
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

        /* frida-java-bridge bundle: globalThis.Java = __fjb.default */
        {
            JSValue rv = JS_Eval(g_js_ctx, kFjbBundle, strlen(kFjbBundle),
                                 "<fjb>", JS_EVAL_TYPE_GLOBAL);
            if (JS_IsException(rv)) {
                JSValue exc = JS_GetException(g_js_ctx);
                const char *msg = JS_ToCString(g_js_ctx, exc);
                snprintf(err, errlen, "fjb error: %s", msg ? msg : "?");
                __android_log_print(ANDROID_LOG_ERROR, "green-agent",
                    "fjb eval: %s", msg ? msg : "?");
                if (msg)
                    JS_FreeCString(g_js_ctx, msg);
                JS_FreeValue(g_js_ctx, exc);
                pthread_mutex_unlock(&g_js_lock);
                return -1;
            }
            JS_FreeValue(g_js_ctx, rv);
        }
        {
            static const char kFjbGlue[] =
                "globalThis.Java = globalThis.__fjb.default; "
                "delete globalThis.__fjb;";
            JSValue glue = JS_Eval(g_js_ctx, kFjbGlue, strlen(kFjbGlue),
                                   "<fjb-glue>", JS_EVAL_TYPE_GLOBAL);
            if (JS_IsException(glue)) {
                JSValue exc = JS_GetException(g_js_ctx);
                const char *msg = JS_ToCString(g_js_ctx, exc);
                snprintf(err, errlen, "fjb glue: %s", msg ? msg : "?");
                if (msg)
                    JS_FreeCString(g_js_ctx, msg);
                JS_FreeValue(g_js_ctx, exc);
                pthread_mutex_unlock(&g_js_lock);
                return -1;
            }
            JS_FreeValue(g_js_ctx, glue);
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

    if (request->command == GREEN_AGENT_CMD_JS_EVAL) {
        char eval_path[300];
        char *epath;
        int efd;
        char code[8192];
        ssize_t cn;
        JSValue crv, jres;
        char *jstr;

        epath = strrchr(path, '/');
        if (!epath)
            return -ENOENT;
        snprintf(eval_path, sizeof(eval_path), "%.*sgreen_eval.js",
                 (int)(epath - path) + 1, path);
        efd = open(eval_path, O_RDONLY);
        if (efd < 0) {
            snprintf(response->message, sizeof(response->message),
                     "eval script not found");
            return -ENOENT;
        }
        cn = read(efd, code, sizeof(code) - 1);
        close(efd);
        if (cn < 0)
            cn = 0;
        code[cn] = '\0';

        pthread_mutex_lock(&g_js_lock);
        JS_UpdateStackTop(g_js_rt);
        crv = JS_Eval(g_js_ctx, code, (size_t)cn, "<green-eval>",
                      JS_EVAL_TYPE_GLOBAL);
        if (JS_IsException(crv)) {
            JSValue exc = JS_GetException(g_js_ctx);
            const char *msg = JS_ToCString(g_js_ctx, exc);
            snprintf(response->message, sizeof(response->message),
                     "eval error: %s", msg ? msg : "?");
            if (msg)
                JS_FreeCString(g_js_ctx, msg);
            JS_FreeValue(g_js_ctx, exc);
            pthread_mutex_unlock(&g_js_lock);
            return -EIO;
        }
        jres = JS_JSONStringify(g_js_ctx, crv, JS_UNDEFINED, JS_UNDEFINED);
        JS_FreeValue(g_js_ctx, crv);
        if (JS_IsException(jres)) {
            JS_FreeValue(g_js_ctx, jres);
            pthread_mutex_unlock(&g_js_lock);
            snprintf(response->message, sizeof(response->message), "null");
            return 0;
        }
        jstr = JS_ToCString(g_js_ctx, jres);
        snprintf(response->message, sizeof(response->message), "%s",
                 jstr ? jstr : "null");
        if (jstr)
            JS_FreeCString(g_js_ctx, jstr);
        JS_FreeValue(g_js_ctx, jres);
        pthread_mutex_unlock(&g_js_lock);
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

static JSValue js_native_broker_log(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv)
{
    const char *msg;
    (void)this_val;
    if (argc >= 1) {
        msg = JS_ToCString(ctx, argv[0]);
        if (msg) {
            __android_log_print(ANDROID_LOG_INFO, "green-js", "%s", msg);
            green_agent_broker_log(msg, strlen(msg));
            JS_FreeCString(ctx, msg);
        }
    }
    return JS_UNDEFINED;
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
    /* Full frida embedded init BEFORE any glib/JS allocation: installs
     * glib thread/fd callbacks, the gum allocator and runs glib_init. */
    extern void gum_init_embedded (void);
    gum_init_embedded();
    pthread_once(&green_agent_once, green_agent_start_once);
}

/* ====================================================================== */
/* Frida-style API engine: arm64 call dispatcher, r-x trampoline slots,   */
/* Interceptor.attach (prologue relocation is done server-side),          */
/* NativeCallback slots and safe memory/file primitives.                  */
/* ====================================================================== */

/* Calls fn with args[0..7] loaded into x0-x7; returns the raw x0. */
__attribute__((naked)) int64_t green_call_asm(const void *fn,
                                              const int64_t *args, int nargs)
{
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x9, x0\n"
        "mov x10, x1\n"
        "ldp x0, x1, [x10]\n"
        "ldp x2, x3, [x10, #16]\n"
        "ldp x4, x5, [x10, #32]\n"
        "ldp x6, x7, [x10, #48]\n"
        "blr x9\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n");
}

#define GREEN_SLOT_PAGES 32
#define GREEN_MAX_HOOKS 32
#define GREEN_MAX_CBS 32

static uint8_t *g_slots;
static volatile uint32_t g_current_hook_id;
static volatile uint32_t g_current_cb_id;

struct green_attach_ctx {
    int used;
    uint64_t orig_cont;
    JSValue onenter;
    JSValue onleave;
};
static struct green_attach_ctx g_attach[GREEN_MAX_HOOKS];

struct green_cb_ctx {
    int used;
    JSValue fn;
};
static struct green_cb_ctx g_cbs[GREEN_MAX_CBS];

static int green_slots_init(void)
{
    if (g_slots)
        return 0;
    g_slots = mmap(NULL, (size_t)GREEN_SLOT_PAGES * 4096,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_slots == MAP_FAILED) {
        g_slots = NULL;
        return -1;
    }
    return 0;
}

/* The redirect of every Interceptor.attach lands here.  The slot stub
 * publishes the hook id, then jumps in with the live x0-x7. */
int64_t green_agent_attach_trampoline(int64_t a0, int64_t a1, int64_t a2,
                                      int64_t a3, int64_t a4, int64_t a5,
                                      int64_t a6, int64_t a7)
{
    struct green_attach_ctx *c;
    int64_t vals[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
    int64_t ret;
    JSValue args;
    JSValue argv[1];
    JSValue rv;

    if (g_current_hook_id >= GREEN_MAX_HOOKS)
        return 0;
    c = &g_attach[g_current_hook_id];
    if (!c->used || !c->orig_cont)
        return 0;

    if (!JS_IsUndefined(c->onenter)) {
        pthread_mutex_lock(&g_js_lock);
        JS_UpdateStackTop(g_js_rt);
        args = JS_NewArray(g_js_ctx);
        for (int i = 0; i < 8; i++)
            JS_SetPropertyUint32(g_js_ctx, args, (uint32_t)i,
                                 JS_NewInt64(g_js_ctx, vals[i]));
        argv[0] = args;
        rv = JS_Call(g_js_ctx, c->onenter, JS_UNDEFINED, 1, argv);
        JS_FreeValue(g_js_ctx, rv);
        JS_FreeValue(g_js_ctx, args);
        pthread_mutex_unlock(&g_js_lock);
    }

    ret = green_call_asm((const void *)(uintptr_t)c->orig_cont, vals, 8);

    if (!JS_IsUndefined(c->onleave)) {
        pthread_mutex_lock(&g_js_lock);
        JS_UpdateStackTop(g_js_rt);
        argv[0] = JS_NewInt64(g_js_ctx, ret);
        rv = JS_Call(g_js_ctx, c->onleave, JS_UNDEFINED, 1, argv);
        if (JS_IsException(rv)) {
            JSValue exc = JS_GetException(g_js_ctx);
            const char *emsg = JS_ToCString(g_js_ctx, exc);
            __android_log_print(ANDROID_LOG_ERROR, "green-debug",
                "onleave JS error: %s", emsg ? emsg : "?");
            if (emsg) JS_FreeCString(g_js_ctx, emsg);
            JS_FreeValue(g_js_ctx, exc);
        } else if (!JS_IsUndefined(rv)) {
            int64_t v = ret;
            JS_ToInt64(g_js_ctx, &v, rv);
            ret = v;
        }
        JS_FreeValue(g_js_ctx, rv);
        pthread_mutex_unlock(&g_js_lock);
    }
    return ret;
}

/* NativeCallback landing zone: the cb stub publishes the callback id. */
int64_t green_agent_callback_trampoline(int64_t a0, int64_t a1, int64_t a2,
                                        int64_t a3, int64_t a4, int64_t a5,
                                        int64_t a6, int64_t a7)
{
    struct green_cb_ctx *c;
    int64_t vals[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
    int64_t out = 0;
    JSValue args;
    JSValue argv[1];
    JSValue rv;

    if (g_current_cb_id >= GREEN_MAX_CBS)
        return 0;
    c = &g_cbs[g_current_cb_id];
    if (!c->used)
        return 0;

    pthread_mutex_lock(&g_js_lock);
    JS_UpdateStackTop(g_js_rt);
    args = JS_NewArray(g_js_ctx);
    for (int i = 0; i < 8; i++)
        JS_SetPropertyUint32(g_js_ctx, args, (uint32_t)i,
                             JS_NewInt64(g_js_ctx, vals[i]));
    argv[0] = args;
    rv = JS_Call(g_js_ctx, c->fn, JS_UNDEFINED, 1, argv);
    if (JS_IsException(rv)) {
        JSValue exc = JS_GetException(g_js_ctx);
        const char *msg = JS_ToCString(g_js_ctx, exc);
        __android_log_print(ANDROID_LOG_ERROR, "green-agent",
                            "callback error: %s", msg ? msg : "?");
        if (msg)
            JS_FreeCString(g_js_ctx, msg);
        JS_FreeValue(g_js_ctx, exc);
    } else {
        JS_ToInt64(g_js_ctx, &out, rv);
    }
    JS_FreeValue(g_js_ctx, rv);
    JS_FreeValue(g_js_ctx, args);
    pthread_mutex_unlock(&g_js_lock);
    return out;
}

static JSValue js_native_interceptor_attach(JSContext *ctx,
                                            JSValueConst this_val, int argc,
                                            JSValueConst *argv)
{
    static GumArm64Writer writer;
    GumArm64Relocator relocator;
    uint64_t target = 0;
    int64_t status;
    uint8_t *slot;
    uint8_t page[4096];
    ssize_t n;
    gsize reloc_size = 0;
    int id;
    int fd;

    (void)this_val;
    if (argc < 3 || JS_ToInt64(ctx, (int64_t *)&target, argv[0]) != 0 ||
        (target & 3) != 0)
        return JS_ThrowInternalError(ctx,
                                     "attach(target, onEnter, onLeave)");
    if (green_slots_init() != 0)
        return JS_ThrowInternalError(ctx, "cannot allocate trampoline slots");
    for (id = 0; id < GREEN_MAX_HOOKS; id++) {
        if (!g_attach[id].used)
            break;
    }
    if (id == GREEN_MAX_HOOKS)
        return JS_ThrowInternalError(ctx, "too many attached hooks");

    slot = g_slots + (size_t)id * 4096;

    /* Save the original bytes before we overwrite the entry with our
     * redirect (the relocator reads the LIVE target page, which is the
     * shadow view after patching). */
    uint32_t orig_bytes[8];
    memcpy(orig_bytes, (const void *)(uintptr_t)target, sizeof(orig_bytes));


    /* 1. Relocate the first instructions of the target into slot+32. */
    gum_arm64_writer_init(&writer, slot + 32);
    writer.pc = target;
    gum_arm64_relocator_init(&relocator, (const gconstpointer)target,
                             &writer);
    /* Relocate instructions until we have enough bytes for the redirect
     * (16), or until the function body ends (eob from ret/b).  For small
     * functions the relocated code IS the complete function; for larger
     * ones we append a jump-back to target+reloc_size. */
    int hit_eob = 0;

    /* NOTE: read_one returns the CUMULATIVE byte offset consumed so far
     * (input_cur - input_start), NOT the instruction count.  See
     * guminterceptor-arm64.c: reloc_bytes = read_one(); while (bytes < sz). */
    while (reloc_size < 16) {
        gsize total_bytes = gum_arm64_relocator_read_one(&relocator, NULL);
        uint32_t insn_index;

        if (total_bytes == 0)
            break;
        insn_index = (total_bytes / 4) - 1;
        gum_arm64_relocator_write_one(&relocator);
        reloc_size = total_bytes;
        /* Detect RET manually: capstone v6 may not set the relocator's
         * eob flag for d65f03c0 (ret). */
        if ((orig_bytes[insn_index] & 0xFFFFFC1F) == 0xD65F0000) {
            hit_eob = 1;
            break;
        }
        if (gum_arm64_relocator_eob(&relocator)) {
            hit_eob = 1;
            break;
        }
    }
    if (reloc_size < 4) {
        gum_arm64_writer_clear(&writer);
        gum_arm64_relocator_clear(&relocator);
        return JS_ThrowInternalError(ctx,
            "could not relocate any instructions from target");
    }
    if (!hit_eob) {
        /* Append a jump-back to the shadow page at target+reloc_size so
         * the original body continues.  This is needed even for small
         * reloc_size (the relocator may not consume the full 16 bytes). */
        gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16,
                                             target + reloc_size);
        gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    }
    /* If hit_eob, the relocated code contains add+ret — self-contained:
     * the ret returns directly to the caller (green_call_asm's BLR). */
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);
    gum_arm64_relocator_clear(&relocator);

    /* 2. Slot head dispatch stub: publish the hook id, then jump. */
    {
        uint32_t words[3] = {
            0x52800000u | ((uint32_t)id << 5) | 17u, /* MOVZ W17, #id */
            0x58000050u,                             /* LDR X16, [PC, #8] */
            0xD61F0200u,                             /* BR X16 */
        };
        uint64_t lit = (uint64_t)(uintptr_t)green_agent_attach_trampoline;

        memcpy(slot + 0, words, sizeof(words));
        memcpy(slot + 12, &lit, sizeof(lit));
    }

    /* 3. Redirect the target entry to the slot via the broker. */
    if (g_maps_count == 0)
        green_maps_refresh();
    if (!green_addr_ok(target & ~4095ULL, 4096, GREEN_PROT_R)) {
        green_maps_refresh();
        if (!green_addr_ok(target & ~4095ULL, 4096, GREEN_PROT_R))
            return JS_ThrowInternalError(ctx, "target page unreadable");
    }
    memcpy(page, (const void *)(uintptr_t)(target & ~4095ULL), sizeof(page));
    {
        uint32_t redirect[2] = { 0x58000050u, 0xD61F0200u };
        uint64_t lit = (uint64_t)(uintptr_t)slot;
        gsize off = (gsize)(target & 4095ULL);

        memcpy(page + off, redirect, sizeof(redirect));
        memcpy(page + off + 8, &lit, sizeof(lit));
    }
    status = green_agent_broker_request_full(GREEN_BROKER_PATCH,
                                             target & ~4095ULL, 0, page,
                                             sizeof(page), NULL);
    if (status != 0)
        return JS_ThrowInternalError(ctx, "broker attach failed: %d",
                                     (int)status);

    /* 4. Make the slot executable. */
    if (mprotect(slot, 4096, PROT_READ | PROT_EXEC) != 0)
        return JS_ThrowInternalError(ctx, "mprotect slot failed");;

    g_attach[id].used = 1;
    g_attach[id].orig_cont = (uint64_t)(uintptr_t)(slot + 32);
    g_attach[id].onenter = JS_IsUndefined(argv[1]) ? JS_UNDEFINED
                                                    : JS_DupValue(ctx, argv[1]);
    g_attach[id].onleave = JS_IsUndefined(argv[2]) ? JS_UNDEFINED
                                                    : JS_DupValue(ctx, argv[2]);
    return JS_NewInt32(ctx, id);
}

static JSValue js_native_new_callback(JSContext *ctx, JSValueConst this_val,
                                      int argc, JSValueConst *argv)
{
    static char page[4096];
    int fd;
    ssize_t n;
    uint32_t words[3];
    uint64_t lit;
    uint64_t slot;
    int id;
    int64_t status;

    (void)this_val;
    if (argc < 1 || !JS_IsFunction(ctx, argv[0]))
        return JS_ThrowInternalError(ctx, "NativeCallback needs a function");
    if (green_slots_init() != 0)
        return JS_ThrowInternalError(ctx, "cannot allocate trampoline slots");
    for (id = 0; id < GREEN_MAX_CBS; id++) {
        if (!g_cbs[id].used)
            break;
    }
    if (id == GREEN_MAX_CBS)
        return JS_ThrowInternalError(ctx, "too many callbacks");

    slot = (uint64_t)(uintptr_t)(g_slots + (size_t)id * 4096);

    /* Stub: MOVZ W17, #id; LDR X16, [PC, #8]; BR X16; .quad trampoline. */
    words[0] = 0x52800000u | ((uint32_t)id << 5) | 17u;
    words[1] = 0x58000050u;
    words[2] = 0xD61F0200u;
    lit = (uint64_t)(uintptr_t)green_agent_callback_trampoline;

    memcpy((void *)(uintptr_t)slot + 0, words, sizeof(words));
    memcpy((void *)(uintptr_t)slot + 12, &lit, sizeof(lit));
    if (mprotect((void *)(uintptr_t)slot, 4096, PROT_READ | PROT_EXEC) != 0)
        return JS_ThrowInternalError(ctx, "mprotect slot failed");
    (void)status;

    g_cbs[id].used = 1;
    g_cbs[id].fn = JS_DupValue(ctx, argv[0]);
    return JS_NewInt64(ctx, (int64_t)slot);
}

static JSValue js_native_mem_write(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    uint64_t address = 0;
    size_t abuf_size = 0;
    uint8_t *data;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&address, argv[0]) != 0)
        return JS_FALSE;
    address = GREEN_UNTAG(address);
    data = JS_GetArrayBuffer(ctx, &abuf_size, argv[1]);
    if (data == NULL)
        return JS_FALSE;
    if (g_maps_count == 0)
        green_maps_refresh();
    if (!green_addr_ok(address, abuf_size, GREEN_PROT_W)) {
        green_maps_refresh();
        if (!green_addr_ok(address, abuf_size, GREEN_PROT_W))
            return JS_FALSE;
    }
    memcpy((void *)(uintptr_t)address, data, abuf_size);
    return JS_TRUE;
}


static JSValue js_native_mem_alloc(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    int64_t size = 4096;
    void *p;

    (void)this_val;
    if (argc >= 1)
        JS_ToInt64(ctx, &size, argv[0]);
    if (size <= 0)
        size = 4096;
    p = malloc((size_t)size);
    if (!p)
        return JS_NULL;
    memset(p, 0, (size_t)size);
    return JS_NewInt64(ctx, (int64_t)GREEN_UNTAG((uintptr_t)p));
}

static JSValue js_native_mem_free(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    uint64_t address = 0;

    (void)this_val;
    if (argc >= 1 && JS_ToInt64(ctx, (int64_t *)&address, argv[0]) == 0)
        free((void *)(uintptr_t)GREEN_UNTAG(address));
    return JS_UNDEFINED;
}

static JSValue js_native_mprotect(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    uint64_t address = 0;
    int64_t length = 0, prot = 0;

    (void)this_val;
    if (argc < 3 || JS_ToInt64(ctx, (int64_t *)&address, argv[0]) != 0 ||
        JS_ToInt64(ctx, &length, argv[1]) != 0 ||
        JS_ToInt64(ctx, &prot, argv[2]) != 0)
    address = GREEN_UNTAG(address);
        return JS_FALSE;
    return mprotect((void *)(uintptr_t)address, (size_t)length,
                    (int)prot) == 0 ? JS_TRUE : JS_FALSE;
}

static JSValue js_native_dlopen(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    const char *path;
    void *handle;

    (void)this_val;
    if (argc < 1)
        return JS_NULL;
    path = JS_ToCString(ctx, argv[0]);
    if (!path)
        return JS_NULL;
    handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    JS_FreeCString(ctx, path);
    if (!handle)
        return JS_NULL;
    /* Android 15 returns PAC-signed soinfo handles (>2^53); a JS Number
     * round-trip would lose precision.  Hand out a small table ID instead. */
    for (int i = 0; i < GREEN_MAX_DLH; i++) {
        if (g_dl_handles[i] == NULL) {
            g_dl_handles[i] = handle;
            return JS_NewInt32(ctx, i + 1);
        }
    }
    return JS_NULL;
}

static JSValue js_native_dlsym(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
    const char *name;
    uint64_t handle = 0;
    void *sym;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&handle, argv[0]) != 0)
        return JS_NULL;
    if (handle > 0 && handle <= GREEN_MAX_DLH) {
        /* dlopen() table ID issued by js_native_dlopen() */
        if (g_dl_handles[handle - 1] == NULL)
            return JS_NULL;
        handle = (uint64_t)(uintptr_t)g_dl_handles[handle - 1];
    } else if (handle > 0) {
        /* Raw pointer passed from script: mask the PAC tag if present. */
        handle = GREEN_UNTAG(handle);
    }
    name = JS_ToCString(ctx, argv[1]);
    if (!name)
        return JS_NULL;
    sym = dlsym((void *)(uintptr_t)handle, name);
    JS_FreeCString(ctx, name);
    if (!sym)
        return JS_NULL;
    return JS_NewInt64(ctx, (int64_t)(uintptr_t)sym);
}

static JSValue js_native_gettid(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    (void)argv;
    return JS_NewInt32(ctx, (int32_t)gettid());
}

static JSValue js_native_sleep(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
    int64_t ms = 0;

    (void)this_val;
    if (argc >= 1)
        JS_ToInt64(ctx, &ms, argv[1 - 1]);
    if (ms > 0)
        usleep((useconds_t)ms * 1000);
    return JS_UNDEFINED;
}

static JSValue js_native_file_write(JSContext *ctx, JSValueConst this_val,
                                    int argc, JSValueConst *argv)
{
    const char *path;
    size_t size = 0;
    uint8_t *data;
    FILE *fp;

    (void)this_val;
    if (argc < 2)
        return JS_FALSE;
    path = JS_ToCString(ctx, argv[0]);
    if (!path)
        return JS_FALSE;
    data = JS_GetArrayBuffer(ctx, &size, argv[1]);
    if (!data) {
        size_t slen;
        const char *s = JS_ToCStringLen(ctx, &slen, argv[1]);
        if (!s) {
            JS_FreeCString(ctx, path);
            return JS_FALSE;
        }
        fp = fopen(path, "wb");
        if (!fp) {
            JS_FreeCString(ctx, path);
            return JS_FALSE;
        }
        fwrite(s, 1, slen, fp);
        JS_FreeCString(ctx, s);
    } else {
        fp = fopen(path, "wb");
        if (!fp) {
            JS_FreeCString(ctx, path);
            return JS_FALSE;
        }
        fwrite(data, 1, size, fp);
    }
    fclose(fp);
    JS_FreeCString(ctx, path);
    return JS_TRUE;
}

/* __green_native_call(fnAddr, [a0..a7]) -> BigInt result */
static JSValue js_native_call(JSContext *ctx, JSValueConst this_val,
                              int argc, JSValueConst *argv)
{
    uint64_t fn = 0;
    int64_t args[8] = {0};
    JSValue item;
    int64_t v;
    int i;
    int64_t ret;

    (void)this_val;
    if (argc < 2 || JS_ToInt64(ctx, (int64_t *)&fn, argv[0]) != 0 ||
        !JS_IsArray(ctx, argv[1]))
        return JS_ThrowInternalError(ctx, "native_call(fn, args[])");
    for (i = 0; i < 8; i++) {
        item = JS_GetPropertyUint32(ctx, argv[1], (uint32_t)i);
        if (JS_IsException(item))
            return JS_EXCEPTION;
        if (!JS_IsUndefined(item) && JS_ToInt64(ctx, &v, item) == 0)
            args[i] = v;
        JS_FreeValue(ctx, item);
    }
    ret = green_call_asm((const void *)(uintptr_t)fn, args, 8);
    return JS_NewBigInt64(ctx, ret);
}
