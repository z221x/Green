/* ======================================================================
 * Java (ART) bridge — Java.perform / Java.use / .implementation hooks.
 *
 * Android 15 specifics:
 *   - jobject/jclass references are MTE-tagged heap pointers that cannot
 *     survive a JS Number round-trip; global refs live in a table and
 *     scripts only see 1-based IDs.
 *   - ArtMethod layout (jni/quick entrypoint offsets) is calibrated at
 *     runtime by comparing a native method (String.intern) against a
 *     plain one (String.length).
 *
 * Hooking (YAHFA-style): the original ArtMethod gets ACC_NATIVE set, its
 * JNI entry pointed at a per-hook thunk, and its quick entry at the
 * generic JNI trampoline.  The original stays callable through a
 * memcpy'd backup ArtMethod invoked via env->Call*MethodA().
 *
 * Limitations (v1): hook entry captures at most 6 Java args (x2..x7);
 * float/double args and float/double returns of hooked methods are not
 * marshalled; everything else goes through full JNI calls.
 * ====================================================================== */

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <android/log.h>
#include <pthread.h>
#include <quickjs.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "green-java", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "green-java", __VA_ARGS__)

/* from green_agent.c */
extern JSContext *g_js_ctx;
extern JSRuntime *g_js_rt;
extern pthread_mutex_t g_js_lock;

#define GREEN_MAX_JOBJ   256   /* global-ref handle table          */
#define GREEN_MAX_JHOOK   64   /* simultaneous Java method hooks   */
#define GREEN_KNATIVE   0x100  /* ACC_NATIVE                       */

typedef struct {
    uint8_t *orig_mid;    /* ArtMethod* of the hooked method        */
    void    *orig_quick;  /* its original quick entrypoint          */
    uint8_t *backup;      /* copy of the original ArtMethod         */
    uint8_t *thunk;       /* r-x: MOVZ W17,#idx ; jump entry        */
    JSValue  fn;          /* JS replacement                         */
    jclass   cls;         /* global ref of the declaring class      */
    char    *name;        /* method name                            */
    char    *sig;         /* full JNI signature                     */
    char     ret;         /* return type char                       */
    char     args[24];    /* parsed argument type chars             */
    int      nargs;
    int      is_static;
    int      used;
} GreenJavaHook;

/* Per-thread hook context so the JS replacement can call the original
 * (this.method(...)) — supports nested hooks on one thread. */
typedef struct {
    JNIEnv  *env;
    jobject  recv;        /* instance receiver, NULL for static    */
    jclass   cls;
    uint8_t *backup;      /* ArtMethod copy to invoke              */
    char     ret;
    int      hook_idx;
} GreenJCtx;

static JavaVM *g_java_vm;
static int g_java_calibrated;
static int g_am_quick_off = -1;
static int g_am_jni_off   = -1;
static int g_am_size      = 32;
static void *g_generic_jni_trampoline;
static jclass g_jcls_string;
static jmethodID g_jm_class_getname;
static char *g_jirt_table;   /* global IndirectRefTable entries */
static __thread int g_java_entry_idx;

/* Decodes an index-id global/local handle to the raw object pointer. */
static void *green_jobj_raw(jobject handle)
{
    uint32_t idx;

    if (handle == NULL)
        return NULL;
    idx = (uint32_t)((uintptr_t)handle >> 2);
    if (g_jirt_table == NULL)
        return NULL;
    return *(void **)(g_jirt_table + (size_t)idx * 16);
}
static void *g_jobj[GREEN_MAX_JOBJ];
static GreenJavaHook g_jhook[GREEN_MAX_JHOOK];
static __thread GreenJCtx g_jctx[8];
static __thread int g_jctx_sp;

/* ------------------------------------------------------------------ */
/* Environment                                                          */
/* ------------------------------------------------------------------ */

static JNIEnv *green_jni_env(void)
{
    JNIEnv *env = NULL;

    if (g_java_vm == NULL)
        return NULL;
    if ((*g_java_vm)->GetEnv(g_java_vm, (void **)&env, JNI_VERSION_1_6)
            == JNI_OK && env != NULL)
        return env;
    if ((*g_java_vm)->AttachCurrentThread(g_java_vm, &env, NULL) == JNI_OK)
        return env;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* In-memory ELF export resolution (linker-namespace-proof).            */
/* ------------------------------------------------------------------ */

#include <elf.h>

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
            /* First mapping (offset 0) holds the ELF header. */
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
        Elf64_Phdr *ph;
        Elf64_Dyn *dyn = NULL;
        Elf64_Sym *symtab = NULL;
        const char *strtab = NULL;
        uint64_t hash = 0, gnu_hash = 0;
        int i;

        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
            return NULL;
        ph = (Elf64_Phdr *)(base + eh->e_phoff);
        for (i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type == PT_DYNAMIC)
                dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
        }
        if (dyn == NULL)
            return NULL;
        for (; dyn->d_tag != DT_NULL; dyn++) {
            switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr); break;
            case DT_STRTAB: strtab = (const char *)(base + dyn->d_un.d_ptr); break;
            case DT_HASH:   hash = dyn->d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = dyn->d_un.d_ptr; break;
            }
        }
        if (symtab == NULL || strtab == NULL)
            return NULL;

        uint32_t nsyms = 0;
        if (hash != 0) {
            /* DT_HASH's nchain == symbol count. */
            nsyms = ((uint32_t *)(base + hash))[1];
        } else if (gnu_hash != 0) {
            /* lld layout heuristic: .dynsym ends where .dynstr begins. */
            nsyms = (uint32_t)((const uint8_t *)strtab
                               - (const uint8_t *)symtab) / sizeof(Elf64_Sym);
        }
        if (nsyms == 0 || nsyms > 4000000)
            return NULL;
        for (i = 0; i < (int)nsyms; i++) {
            if (symtab[i].st_name == 0)
                continue;
            if (strcmp(strtab + symtab[i].st_name, sym_name) == 0 &&
                symtab[i].st_value != 0)
                return (void *)(base + symtab[i].st_value);
        }
    }
    return NULL;
}

static int green_java_init_vm(void)
{
    jint (*get_vms)(JavaVM **, jsize, jsize *);
    JavaVM *vms[1];
    jsize n = 0;

    if (g_java_vm != NULL)
        return 0;
    get_vms = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (get_vms == NULL)
        get_vms = green_module_dlsym("libart.so", "JNI_GetCreatedJavaVMs");
    if (get_vms == NULL)
        get_vms = green_module_dlsym("libnativehelper.so",
                                     "JNI_GetCreatedJavaVMs");
    if (get_vms == NULL) {
        LOGI("JNI_GetCreatedJavaVMs not found in any namespace");
        return -1;
    }
    if (get_vms(vms, 1, &n) != JNI_OK || n < 1)
        return -1;
    g_java_vm = vms[0];
    return 0;
}

/* ArtMethod calibration — port of frida-java-bridge _getArtMethodSpec():
 * scan android.os.Process.getElapsedCpuTime() (public static final
 * native, JNI impl lives in libandroid_runtime.so) for
 *   - the first pointer field inside libandroid_runtime.so  -> jniCode
 *   - the u32 field matching public|static|final|native      -> accessFlags
 * quickCode = jniCode + pointerSize;  size = quickCode + pointerSize. */
static int green_module_range(const char *mod_name, uint64_t *start,
                              uint64_t *end)
{
    FILE *maps;
    char line[512];
    unsigned long long lo = 0, hi = 0;

    maps = fopen("/proc/self/maps", "re");
    if (maps == NULL)
        return -1;
    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, mod_name) != NULL) {
            unsigned long long s0, e0;
            if (sscanf(line, "%llx-%llx", &s0, &e0) == 2) {
                if (lo == 0)
                    lo = s0;
                hi = e0;
            }
        }
    }
    fclose(maps);
    if (lo == 0)
        return -1;
    *start = lo;
    *end = hi;
    return 0;
}

static int green_java_calibrate(void)
{
    JNIEnv *env;
    jclass cls;
    jmethodID mid, intr;
    uint64_t rt_start, rt_end;
    uint64_t mem[8];
    int offset, jni = -1, flags = -1;
    const uint32_t kExpected =
        0x0001 /* public */ | 0x0008 /* static */ |
        0x0010 /* final  */ | 0x0100 /* native */;
    const uint32_t kMask = ~(uint32_t)(0x40000000 /* fastInterp */   |
                                       0x10000000 /* publicApi */    |
                                       0x00200000 /* nterpInvoke */  |
                                       0x00100000 /* nterpEntry */);

    if (g_java_calibrated)
        return 0;
    if (green_java_init_vm() != 0)
        return -1;
    env = green_jni_env();
    if (env == NULL) {
        LOGI("calibrate: no JNIEnv");
        return -1;
    }
    if (green_module_range("libandroid_runtime.so", &rt_start, &rt_end) != 0) {
        LOGI("calibrate: libandroid_runtime not found");
        return -1;
    }

    cls = (*env)->FindClass(env, "android/os/Process");
    if (cls == NULL) {
        (*env)->ExceptionClear(env);
        LOGI("calibrate: FindClass(android/os/Process) failed");
        return -1;
    }
    mid = (*env)->GetStaticMethodID(env, cls, "getElapsedCpuTime", "()J");
    if (mid == NULL) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cls);
        LOGI("calibrate: GetStaticMethodID failed");
        return -1;
    }
    memcpy(mem, mid, sizeof(mem));
    (*env)->DeleteLocalRef(env, cls);

    for (offset = 0; offset < 64 && (jni < 0 || flags < 0); offset += 4) {
        if (jni < 0) {
            uint64_t p = *(uint64_t *)((uint8_t *)mem + offset);
            if (p >= rt_start && p < rt_end)
                jni = offset;
        }
        if (flags < 0) {
            uint32_t f = *(uint32_t *)((uint8_t *)mem + offset);
            if ((f & kMask) == kExpected)
                flags = offset;
        }
    }
    if (jni < 0 || flags < 0) {
        LOGI("calibrate: scan failed jni=%d flags=%d", jni, flags);
        return -1;
    }

    g_am_jni_off = jni;
    g_am_quick_off = jni + 8;
    g_am_size = g_am_quick_off + 8;
    /* The generic JNI trampoline: read the quick entry of a REAL native
     * method (String.intern) — this yields the ClassLinker-relocated
     * copy, which is the address the runtime expects (see
     * frida-java-bridge android.js ~L476). */
    cls = (*env)->FindClass(env, "java/lang/String");
    intr = cls ? (*env)->GetMethodID(env, cls, "intern",
                                     "()Ljava/lang/String;") : NULL;
    if (intr != NULL)
        g_generic_jni_trampoline =
            *(void **)((uint8_t *)intr + g_am_quick_off);
    if (cls != NULL)
        (*env)->DeleteLocalRef(env, cls);
    if (g_generic_jni_trampoline == NULL) {
        LOGI("calibrate: no generic jni trampoline");
        return -1;
    }

    {
        jclass kc = (*env)->FindClass(env, "java/lang/Class");
        if (kc != NULL) {
            g_jm_class_getname = (*env)->GetMethodID(env, kc, "getName",
                "()Ljava/lang/String;");
            (*env)->DeleteLocalRef(env, kc);
        }
        if (g_jm_class_getname == NULL)
            (*env)->ExceptionClear(env);
    }

    /* Calibrate the global-reference table so index-id handles can be
     * decoded to raw object pointers (needed by the quick-convention
     * backup calls).  IrtEntry = { Object* obj; uint32 serial; } = 16B.
     * Method: create two consecutive global refs, then scan JavaVMExt
     * for the table whose entries at both indexes have matching String
     * class words. */
    {
        static char *g_irt_table;
        if (g_irt_table == NULL) {
            jstring s1 = (*env)->NewStringUTF(env, "green_calib_a");
            jstring s2 = (*env)->NewStringUTF(env, "green_calib_b");
            jobject g1 = s1 ? (*env)->NewGlobalRef(env, s1) : NULL;
            jobject g2 = s2 ? (*env)->NewGlobalRef(env, s2) : NULL;
            if (g1 != NULL && g2 != NULL) {
                uint32_t i1 = (uint32_t)((uintptr_t)g1 >> 2);
                uint32_t i2 = (uint32_t)((uintptr_t)g2 >> 2);
                if (i1 != i2 && i1 > 4 && i2 > 4) {
                    int fd = open("/proc/self/mem", O_RDONLY);
                    for (int off = 0; off < 4096 && g_irt_table == NULL;
                         off += 8) {
                        char *p;
                        uint32_t a_cls = 0, b_cls = 0;
                        char *a, *b;
                        if (fd < 0)
                            break;
                        if (pread(fd, &p, 8,
                              (off_t)(intptr_t)((char *)g_java_vm + off)) != 8)
                            continue;
                        if ((uintptr_t)p < 0x10000)
                            continue;
                        if (pread(fd, &a, 8, (off_t)(intptr_t)(p + (size_t)i1 * 16)) != 8 ||
                            pread(fd, &b, 8, (off_t)(intptr_t)(p + (size_t)i2 * 16)) != 8)
                            continue;
                        if (a == NULL || b == NULL || a == b)
                            continue;
                        if ((uintptr_t)a < 0x10000 || (uintptr_t)b < 0x10000)
                            continue;
                        if (pread(fd, &a_cls, 4, (off_t)(intptr_t)a) == 4 &&
                            pread(fd, &b_cls, 4, (off_t)(intptr_t)b) == 4 &&
                            a_cls != 0 && a_cls == b_cls)
                            g_irt_table = p;
                    }
                    if (fd >= 0)
                        close(fd);
                }
            }
            LOGI("calib handles: g1=%p g2=%p (i1=%u i2=%u)",
                 g1, g2,
                 g1 ? (uint32_t)((uintptr_t)g1 >> 2) : 0,
                 g2 ? (uint32_t)((uintptr_t)g2 >> 2) : 0);
            if (g1) (*env)->DeleteGlobalRef(env, g1);
            if (g2) (*env)->DeleteGlobalRef(env, g2);
            if (s1) (*env)->DeleteLocalRef(env, s1);
            if (s2) (*env)->DeleteLocalRef(env, s2);
            LOGI("global IRT table = %p", (void *)g_irt_table);
        }
        g_jirt_table = g_irt_table;
    }

    g_java_calibrated = 1;
    LOGI("calibrated: flags=+%d jni=+%d quick=+%d size=%d tramp=%p",
         flags, g_am_jni_off, g_am_quick_off, g_am_size,
         g_generic_jni_trampoline);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Global-ref handle table                                              */
/* ------------------------------------------------------------------ */

static int green_jobj_put(JNIEnv *env, jobject ref)
{
    jobject g;
    int i;

    if (ref == NULL)
        return 0;
    g = (*env)->NewGlobalRef(env, ref);
    if (g == NULL)
        return 0;
    for (i = 0; i < GREEN_MAX_JOBJ; i++) {
        if (g_jobj[i] == NULL) {
            g_jobj[i] = g;
            return i + 1;
        }
    }
    (*env)->DeleteGlobalRef(env, g);
    return 0;
}

static jobject green_jobj_get(int id)
{
    if (id <= 0 || id > GREEN_MAX_JOBJ)
        return NULL;
    return g_jobj[id - 1];
}

/* Wraps a jobject as a JS value: Strings become JS strings; arrays and
 * other objects become {__greenobj: id, __greencls: name} markers that
 * the prelude converts into instance wrappers. */
static JSValue green_jobj_wrap(JNIEnv *env, jobject o)
{
    const char *u;

    if (o == NULL)
        return JS_NULL;
    if (g_jcls_string != NULL && (*env)->IsInstanceOf(env, o, g_jcls_string)) {
        u = (*env)->GetStringUTFChars(env, o, NULL);
        if (u != NULL) {
            JSValue v = JS_NewString(g_js_ctx, u);
            (*env)->ReleaseStringUTFChars(env, o, u);
            return v;
        }
    }
    {
        JSValue m = JS_NewObject(g_js_ctx);
        jclass k = (*env)->GetObjectClass(env, o);
        jstring jn = (k != NULL && g_jm_class_getname != NULL)
            ? (*env)->CallObjectMethod(env, k, g_jm_class_getname) : NULL;
        u = jn ? (*env)->GetStringUTFChars(env, jn, NULL) : NULL;
        JS_SetPropertyStr(g_js_ctx, m, "__greenobj",
                          JS_NewInt32(g_js_ctx, green_jobj_put(env, o)));
        JS_SetPropertyStr(g_js_ctx, m, "__greencls",
            JS_NewString(g_js_ctx, u ? u : "?"));
        if (u != NULL)
            (*env)->ReleaseStringUTFChars(env, jn, u);
        if (jn != NULL)
            (*env)->DeleteLocalRef(env, jn);
        if (k != NULL)
            (*env)->DeleteLocalRef(env, k);
        (*env)->ExceptionClear(env);
        return m;
    }
}

/* ------------------------------------------------------------------ */
/* Hook entry: thunk(W17=idx) -> naked -> body                          */
/* ------------------------------------------------------------------ */

__attribute__((used, noinline))
static void green_java_set_entry_idx(int idx)
{
    g_java_entry_idx = idx;
}

__attribute__((used, noinline, visibility("default")))
int64_t green_java_hook_body(JNIEnv *env, jobject thiz_or_cls,
                             int64_t a1, int64_t a2, int64_t a3,
                             int64_t a4, int64_t a5, int64_t a6);

__attribute__((used, naked, noinline, visibility("default")))
void green_java_hook_entry(void)
{
    /* Preserve the JNI argument registers while a small C helper records
     * the per-thunk index in TLS. The body then receives the original
     * x0..x7 values with no dependency on compiler-generated stack layout.
     *
     * This entrypoint is reached through a tail branch from ART's generic
     * JNI trampoline, so x30 still contains ART's return address.  Both BL
     * calls below overwrite x30; preserve it explicitly or the final RET
     * loops back into this epilogue (and eventually corrupts the stack).
     */
    __asm__ volatile(
        "stp x0, x1, [sp, #-80]!\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "str x30, [sp, #64]\n"
        "mov w0, w17\n"
        "bl green_java_set_entry_idx\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "bl green_java_hook_body\n"
        "ldr x30, [sp, #64]\n"
        "add sp, sp, #80\n"
        "ret\n");
}

static int green_java_make_thunk(int idx, uint8_t **out)
{
    static uint8_t *area;
    uint32_t words[3];
    uint64_t lit = (uint64_t)(uintptr_t)green_java_hook_entry;

    if (area == NULL) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return -1;
        area = p;
    }
    if ((size_t)(idx + 1) * 16 > 4096)
        return -1;
    words[0] = 0x52800000u | ((uint32_t)(idx & 0xffff) << 5) | 17u;
    /* Keep the hook index in W17; load the entry address into X16. */
    words[1] = 0x58000050u;
    words[2] = 0xD61F0200u;
    /* Page may already be RX from a previous thunk: make it writable. */
    if (mprotect(area, 4096, PROT_READ | PROT_WRITE) != 0)
        return -1;
    memcpy(area + idx * 16, words, 12);
    memcpy(area + idx * 16 + 12, &lit, 8);
    if (mprotect(area, 4096, PROT_READ | PROT_EXEC) != 0)
        return -1;
    __builtin___clear_cache((char *)(area + idx * 16),
                            (char *)(area + idx * 16) + 20);
    *out = area + idx * 16;
    return 0;
}

int64_t green_java_hook_body(JNIEnv *env, jobject thiz_or_cls,
                             int64_t a1, int64_t a2, int64_t a3,
                             int64_t a4, int64_t a5, int64_t a6)
{
    int idx = g_java_entry_idx;
    GreenJavaHook *h;
    GreenJCtx *c;
    int64_t vals[6] = { a1, a2, a3, a4, a5, a6 };
    JSValue argv[8];
    JSValue r = JS_UNDEFINED;
    int64_t rv = 0;
    int i;

    {
        static int hits = 0;
        if (hits < 3)
            LOGI("hook body entered: idx=%d sp=%d", idx, g_jctx_sp);
        hits++;
    }
    if (idx < 0 || idx >= GREEN_MAX_JHOOK || g_jctx_sp >= 8)
        return 0;
    h = &g_jhook[idx];
    if (!h->used)
        return 0;

    c = &g_jctx[g_jctx_sp++];
    c->env = env;
    /* The receiver as passed by the generic JNI trampoline — in a
     * release ART build this is the raw mirror pointer, exactly what
     * the quick-convention backup call needs.  (No global ref: the
     * value must stay as-is for the direct quick call.) */
    c->recv = h->is_static ? NULL : thiz_or_cls;
    c->cls = h->cls;
    c->backup = h->backup;
    c->ret = h->ret;
    c->hook_idx = idx;

    pthread_mutex_lock(&g_js_lock);
    JS_UpdateStackTop(g_js_rt);

    argv[0] = JS_NewInt32(g_js_ctx,
        h->is_static ? 0 : green_jobj_put(env, thiz_or_cls));
    for (i = 0; i < h->nargs && i < 6; i++) {
        char t = h->args[i];
        if (t == 'L' || t == '[') {
            argv[i + 1] = vals[i]
                ? green_jobj_wrap(env, (jobject)(uintptr_t)vals[i])
                : JS_NULL;
        } else if (t == 'J') {
            argv[i + 1] = JS_NewBigInt64(g_js_ctx, vals[i]);
        } else if (t == 'D' || t == 'F') {
            union { int64_t i; double d; } cv;
            cv.i = vals[i];
            argv[i + 1] = JS_NewFloat64(g_js_ctx, cv.d);
        } else {
            argv[i + 1] = JS_NewInt64(g_js_ctx, vals[i]);
        }
    }

    r = JS_Call(g_js_ctx, h->fn, JS_UNDEFINED, h->nargs + 1, argv);
    for (i = 0; i <= h->nargs && i < 8; i++)
        JS_FreeValue(g_js_ctx, argv[i]);

    if (JS_IsException(r)) {
        JSValue exc = JS_GetException(g_js_ctx);
        const char *msg = JS_ToCString(g_js_ctx, exc);
        LOGE(
            "hook '%s': %s", h->name, msg ? msg : "?");
        if (msg)
            JS_FreeCString(g_js_ctx, msg);
        JS_FreeValue(g_js_ctx, exc);
        r = JS_NewInt64(g_js_ctx, 0);
    }

    /* Marshal the JS result back per the method's return type. */
    if (c->ret == 'L' || c->ret == '[') {
        if (JS_IsString(r)) {
            const char *s = JS_ToCString(g_js_ctx, r);
            if (s != NULL) {
                jstring js = (*env)->NewStringUTF(env, s);
                rv = (int64_t)(uintptr_t)js;
                JS_FreeCString(g_js_ctx, s);
            }
        } else if (JS_IsNumber(r)) {
            int32_t id = 0;
            JS_ToInt32(g_js_ctx, &id, r);
            rv = (int64_t)(uintptr_t)green_jobj_get(id);
        }
    } else if (c->ret == 'J') {
        JS_ToInt64(g_js_ctx, &rv, r);
    } else if (c->ret != 'V') {
        int64_t n = 0;
        JS_ToInt64(g_js_ctx, &n, r);
        rv = (int64_t)(int32_t)n;   /* sign-extend 32-bit returns */
    }
    JS_FreeValue(g_js_ctx, r);
    pthread_mutex_unlock(&g_js_lock);

    g_jctx_sp--;
    return rv;
}

/* ------------------------------------------------------------------ */
/* Signature parsing                                                    */
/* ------------------------------------------------------------------ */

/* Extracts argument type chars (L/[ kept as-is, one char each) and the
 * return char.  Returns argument count, or -1 on malformed input. */
static int green_java_parse_sig(const char *sig, char *args, int args_cap,
                                char *ret)
{
    const char *p = sig;
    int n = 0;

    if (p == NULL || *p != '(')
        return -1;
    for (p++; *p && *p != ')';) {
        char t = *p;
        if (n >= args_cap)
            return -1;
        if (t == 'L') {
            args[n++] = 'L';
            while (*p && *p != ';')
                p++;
            if (*p)
                p++;
        } else if (t == '[') {
            args[n++] = '[';
            p++;
            if (*p == 'L')
                while (*p && *p != ';')
                    p++;
            if (*p)
                p++;
        } else if (strchr("ZBCSIJFD", t)) {
            args[n++] = t;
            p++;
        } else {
            return -1;
        }
    }
    if (*p != ')')
        return -1;
    *ret = p[1] ? p[1] : 'V';
    return n;
}

/* Converts one JS argv element into a jvalue slot of type t. */
static int green_java_arg_to_jval(JSContext *ctx, JNIEnv *env, char t,
                                  JSValueConst v, jvalue *out)
{
    switch (t) {
    case 'Z': case 'B': case 'C': case 'S': case 'I': {
        int32_t n = 0;
        JS_ToInt32(ctx, &n, v);
        out->i = n;
        return 0;
    }
    case 'J': {
        int64_t n = 0;
        JS_ToInt64(ctx, &n, v);
        out->j = n;
        return 0;
    }
    case 'F': {
        double d = 0;
        JS_ToFloat64(ctx, &d, v);
        out->f = (jfloat)d;
        return 0;
    }
    case 'D': {
        double d = 0;
        JS_ToFloat64(ctx, &d, v);
        out->d = d;
        return 0;
    }
    case 'L': case '[': {
        if (JS_IsString(v)) {
            const char *s = JS_ToCString(ctx, v);
            if (s == NULL)
                return -1;
            out->l = (*env)->NewStringUTF(env, s);
            JS_FreeCString(ctx, s);
            return 0;
        }
        if (JS_IsObject(v)) {
            JSValue idv = JS_GetPropertyStr(ctx, v, "__greenobj");
            int32_t id = 0;
            JS_ToInt32(ctx, &id, idv);
            JS_FreeValue(ctx, idv);
            out->l = green_jobj_get(id);
            return 0;
        }
        if (JS_IsNumber(v)) {
            int32_t id = 0;
            JS_ToInt32(ctx, &id, v);
            out->l = green_jobj_get(id);
            return 0;
        }
        if (JS_IsNull(v) || JS_IsUndefined(v)) {
            out->l = NULL;
            return 0;
        }
        return -1;
    }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Native JS bindings                                                   */
/* ------------------------------------------------------------------ */

static JSValue js_java_available(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
    JNIEnv *env;

    (void)this_val; (void)argc; (void)argv;
    if (green_java_init_vm() != 0 || green_java_calibrate() != 0)
        return JS_FALSE;
    env = green_jni_env();
    return env != NULL ? JS_TRUE : JS_FALSE;
}

static JSValue js_java_find_class(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    JNIEnv *env;
    const char *name;
    char slash[256];
    jclass cls;
    size_t i;

    (void)this_val;
    if (argc < 1 || !JS_IsString(argv[0]))
        return JS_ThrowInternalError(ctx, "find_class(name)");
    if ((env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "no JVM");
    name = JS_ToCString(ctx, argv[0]);
    if (name == NULL)
        return JS_NULL;
    for (i = 0; name[i] && i < sizeof(slash) - 1; i++)
        slash[i] = name[i] == '.' ? '/' : name[i];
    slash[i] = 0;
    JS_FreeCString(ctx, name);
    cls = (*env)->FindClass(env, slash);
    if (cls == NULL) {
        (*env)->ExceptionClear(env);
        return JS_NULL;
    }
    {
        JSValue v = JS_NewInt32(ctx, green_jobj_put(env, cls));
        (*env)->DeleteLocalRef(env, cls);
        return v;
    }
}

/* Appends the JNI descriptor of a java.lang.Class getName() result. */
static size_t green_jni_append_type(char *sig, size_t cap, size_t sl,
                                    const char *cu)
{
    static const struct { const char *n; char c; } prims[] = {
        { "boolean", 'Z' }, { "byte", 'B' }, { "char", 'C' },
        { "short", 'S' },   { "int", 'I' },  { "long", 'J' },
        { "float", 'F' },   { "double", 'D' }, { "void", 'V' },
    };
    size_t i;

    if (cu == NULL)
        return sl;
    for (i = 0; i < sizeof(prims) / sizeof(prims[0]); i++) {
        if (strcmp(cu, prims[i].n) == 0) {
            if (sl < cap - 1)
                sig[sl++] = prims[i].c;
            return sl;
        }
    }
    if (cu[0] == '[')
        return sl + (size_t)snprintf(sig + sl, cap - sl, "%s", cu);
    {
        char cv[256];
        size_t ci;
        for (ci = 0; cu[ci] && ci < sizeof(cv) - 1; ci++)
            cv[ci] = cu[ci] == '.' ? '/' : cu[ci];
        cv[ci] = 0;
        return sl + (size_t)snprintf(sig + sl, cap - sl, "L%s;", cv);
    }
}

/* __green_java_class_info(clsId) -> {name, methods:[...], ctors:[...]}
 * via java.lang.Class reflection.  methods: {name, sig, static, mid}. */
static JSValue js_java_class_info(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    JNIEnv *env;
    jclass cls, k_class, k_method, k_ctor;
    jmethodID m_getmethods, m_getdmethods, m_getctors, m_getname,
              m_getptypes, m_getrtype, m_getmods, m_getmname;
    jobjectArray arr;
    JSValue out;
    jsize n, i;
    int cls_id;

    (void)this_val;
    if (argc < 1 || (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "class_info(clsId)");
    JS_ToInt32(ctx, &cls_id, argv[0]);
    cls = (jclass)green_jobj_get(cls_id);
    if (cls == NULL)
        return JS_ThrowInternalError(ctx, "bad class handle");

    k_class = (*env)->FindClass(env, "java/lang/Class");
    k_method = (*env)->FindClass(env, "java/lang/reflect/Method");
    k_ctor = (*env)->FindClass(env, "java/lang/reflect/Constructor");
    if (k_class == NULL || k_method == NULL || k_ctor == NULL)
        goto fail;

    m_getname   = (*env)->GetMethodID(env, k_class, "getName",
                                      "()Ljava/lang/String;");
    m_getmname  = (*env)->GetMethodID(env, k_method, "getName",
                                      "()Ljava/lang/String;");
    m_getmods   = (*env)->GetMethodID(env, k_method, "getModifiers", "()I");
    m_getptypes = (*env)->GetMethodID(env, k_method, "getParameterTypes",
                                      "()[Ljava/lang/Class;");
    m_getrtype  = (*env)->GetMethodID(env, k_method, "getReturnType",
                                      "()Ljava/lang/Class;");
    m_getmethods = (*env)->GetMethodID(env, k_class, "getMethods",
                                       "()[Ljava/lang/reflect/Method;");
    m_getdmethods = (*env)->GetMethodID(env, k_class, "getDeclaredMethods",
                                        "()[Ljava/lang/reflect/Method;");
    m_getctors  = (*env)->GetMethodID(env, k_class, "getDeclaredConstructors",
                                      "()[Ljava/lang/reflect/Constructor;");
    if (!m_getname || !m_getmods || !m_getptypes || !m_getrtype ||
        !m_getmethods || !m_getdmethods || !m_getctors)
        goto fail;

    out = JS_NewObject(ctx);
    {
        jstring jn = (*env)->CallObjectMethod(env, cls, m_getname);
        const char *u = jn ? (*env)->GetStringUTFChars(env, jn, NULL) : NULL;
        JS_SetPropertyStr(ctx, out, "name",
            u ? JS_NewString(ctx, u) : JS_NewString(ctx, "?"));
        if (u)
            (*env)->ReleaseStringUTFChars(env, jn, u);
        (*env)->DeleteLocalRef(env, jn);
    }

    /* Members are collected from both getMethods() (public incl. super)
     * and getDeclaredMethods(); Constructor.getModifiers is looked up
     * on Method so skip it here — ctors reuse getParameterTypes. */
    {
        JSValue methods = JS_NewArray(ctx);
        JSValue ctors = JS_NewArray(ctx);
        int mi = 0, ci = 0;
        static const jmethodID sets[2][2] = {{0, 0}, {0, 0}};
        (void)sets;

        for (int pass = 0; pass < 2; pass++) {
            arr = (*env)->CallObjectMethod(env, cls,
                pass ? m_getdmethods : m_getmethods);
            if (arr == NULL) {
                (*env)->ExceptionClear(env);
                continue;
            }
            n = (*env)->GetArrayLength(env, arr);
            for (i = 0; i < n; i++) {
                jobject m = (*env)->GetObjectArrayElement(env, arr, i);
                if (m == NULL)
                    continue;
                {
                    JSValue o = JS_NewObject(ctx);
                    jstring jn = (*env)->CallObjectMethod(env, m, m_getmname);
                    const char *u = jn
                        ? (*env)->GetStringUTFChars(env, jn, NULL) : NULL;
                    JS_SetPropertyStr(ctx, o, "name",
                        u ? JS_NewString(ctx, u) : JS_NewString(ctx, "?"));
                    if (u)
                        (*env)->ReleaseStringUTFChars(env, jn, u);
                    (*env)->DeleteLocalRef(env, jn);

                    /* Build the JNI signature from parameter + return
                     * types. */
                    {
                        jclass rtc = (*env)->CallObjectMethod(env, m,
                                                              m_getrtype);
                        jobjectArray pt = (*env)->CallObjectMethod(env, m,
                                                                   m_getptypes);
                        char sig[512];
                        size_t sl = 0;
                        jint mods = (*env)->CallIntMethod(env, m, m_getmods);
                        jsize pn = pt ? (*env)->GetArrayLength(env, pt) : 0;
                        jsize k;

                        sig[sl++] = '(';
                        for (k = 0; k < pn && sl < sizeof(sig) - 64; k++) {
                            jclass pc = (*env)->GetObjectArrayElement(env,
                                                                      pt, k);
                            jstring cn = (*env)->CallObjectMethod(env, pc,
                                                                  m_getname);
                            const char *cu = cn
                                ? (*env)->GetStringUTFChars(env, cn, NULL)
                                : NULL;
                            if (cu != NULL) {
                                sl = green_jni_append_type(sig,
                                    sizeof(sig), sl, cu);
                                (*env)->ReleaseStringUTFChars(env, cn, cu);
                            }
                            (*env)->DeleteLocalRef(env, cn);
                            (*env)->DeleteLocalRef(env, pc);
                        }
                        sig[sl++] = ')';
                        if (rtc != NULL) {
                            jstring cn = (*env)->CallObjectMethod(env, rtc,
                                                                  m_getname);
                            const char *cu = cn
                                ? (*env)->GetStringUTFChars(env, cn, NULL)
                                : NULL;
                            if (cu != NULL) {
                                sl = green_jni_append_type(sig,
                                    sizeof(sig), sl, cu);
                                (*env)->ReleaseStringUTFChars(env, cn, cu);
                            }
                            (*env)->DeleteLocalRef(env, cn);
                            (*env)->DeleteLocalRef(env, rtc);
                        } else {
                            sig[sl++] = 'V';
                        }
                        sig[sl] = 0;
                        JS_SetPropertyStr(ctx, o, "sig",
                                          JS_NewString(ctx, sig));

                        JS_SetPropertyStr(ctx, o, "static",
                            JS_NewBool(ctx, (mods & 8) != 0));
                        /* mid resolved lazily by JS via get_method_id. */
                        JS_SetPropertyUint32(ctx, methods, mi++, o);
                    }
                    (*env)->DeleteLocalRef(env, m);
                }
            }
            (*env)->DeleteLocalRef(env, arr);
        }

        /* Constructors. */
        {
            jmethodID c_getptypes = (*env)->GetMethodID(env, k_ctor,
                "getParameterTypes", "()[Ljava/lang/Class;");

            if (c_getptypes != NULL) {
                arr = (*env)->CallObjectMethod(env, cls, m_getctors);
                if (arr != NULL) {
                    n = (*env)->GetArrayLength(env, arr);
                    for (i = 0; i < n; i++) {
                        jobject c0 = (*env)->GetObjectArrayElement(env, arr,
                                                                   i);
                        if (c0 == NULL)
                            continue;
                        {
                            JSValue o = JS_NewObject(ctx);
                            jobjectArray pt = (*env)->CallObjectMethod(env,
                                c0, c_getptypes);
                            char sig[512];
                            size_t sl = 0;
                            jsize pn = pt
                                ? (*env)->GetArrayLength(env, pt) : 0;
                            jsize k;
                            sig[sl++] = '(';
                            for (k = 0; k < pn && sl < sizeof(sig) - 64;
                                 k++) {
                                jclass pc = (*env)->GetObjectArrayElement(env,
                                    pt, k);
                                jstring cn = (*env)->CallObjectMethod(env,
                                    pc, m_getname);
                                const char *cu = cn
                                    ? (*env)->GetStringUTFChars(env, cn,
                                                                NULL) : NULL;
                                if (cu != NULL) {
                                    sl = green_jni_append_type(sig,
                                        sizeof(sig), sl, cu);
                                    (*env)->ReleaseStringUTFChars(env, cn,
                                                                  cu);
                                }
                                (*env)->DeleteLocalRef(env, cn);
                                (*env)->DeleteLocalRef(env, pc);
                            }
                            sl += (size_t)snprintf(sig + sl,
                                sizeof(sig) - sl, ")V");
                            JS_SetPropertyStr(ctx, o, "sig",
                                              JS_NewString(ctx, sig));
                            JS_SetPropertyUint32(ctx, ctors, ci++, o);
                        }
                        (*env)->DeleteLocalRef(env, c0);
                    }
                    (*env)->DeleteLocalRef(env, arr);
                }
            }
        }

        JS_SetPropertyStr(ctx, out, "methods", methods);
        JS_SetPropertyStr(ctx, out, "ctors", ctors);
    }

    (*env)->DeleteLocalRef(env, k_class);
    (*env)->DeleteLocalRef(env, k_method);
    (*env)->DeleteLocalRef(env, k_ctor);
    (*env)->ExceptionClear(env);
    return out;
fail:
    (*env)->ExceptionClear(env);
    return JS_ThrowInternalError(ctx, "reflection setup failed");
}

/* __green_java_get_method_id(clsId, name, sig, isStatic) -> mid|0 */
static JSValue js_java_get_method_id(JSContext *ctx, JSValueConst this_val,
                                     int argc, JSValueConst *argv)
{
    JNIEnv *env;
    int cls_id, is_static = 0;
    const char *name, *sig;
    jclass cls;
    jmethodID mid;

    (void)this_val;
    if (argc < 4 || (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "get_method_id(cls,name,sig,st)");
    JS_ToInt32(ctx, &cls_id, argv[0]);
    name = JS_ToCString(ctx, argv[1]);
    sig = JS_ToCString(ctx, argv[2]);
    JS_ToInt32(ctx, &is_static, argv[3]);
    cls = (jclass)green_jobj_get(cls_id);
    if (cls == NULL || name == NULL || sig == NULL) {
        if (name) JS_FreeCString(ctx, name);
        if (sig) JS_FreeCString(ctx, sig);
        return JS_ThrowInternalError(ctx, "bad args");
    }
    mid = is_static
        ? (*env)->GetStaticMethodID(env, cls, name, sig)
        : (*env)->GetMethodID(env, cls, name, sig);
    JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, sig);
    if (mid == NULL) {
        (*env)->ExceptionClear(env);
        return JS_NewInt64(ctx, 0);
    }
    return JS_NewInt64(ctx, (int64_t)(uintptr_t)mid);
}

/* Marshals a JS result per ret char (shared by call/new). */
static JSValue green_java_ret_wrap(JSContext *ctx, JNIEnv *env, char ret,
                                   jvalue v)
{
    switch (ret) {
    case 'V': return JS_UNDEFINED;
    case 'L': case '[': return green_jobj_wrap(env, v.l);
    case 'J': return JS_NewBigInt64(ctx, v.j);
    case 'F': return JS_NewFloat64(ctx, (double)v.f);
    case 'D': return JS_NewFloat64(ctx, v.d);
    default:  return JS_NewInt64(ctx, v.i);
    }
}

/* Calls env->Call*MethodA with jvalue[] built from a JS array. */
static JSValue green_java_do_call(JSContext *ctx, JNIEnv *env, int cls_id,
                                  int obj_id, int64_t mid_raw,
                                  const char *sig, JSValueConst args_val,
                                  int is_static, int is_ctor)
{
    char argt[24];
    char ret = 'V';
    jvalue jv[24];
    JSValue el;
    int n, i, argc = 0;

    n = green_java_parse_sig(sig, argt, (int)sizeof(argt), &ret);
    if (n < 0)
        return JS_ThrowInternalError(ctx, "bad signature: %s", sig);
    if (!JS_IsUndefined(args_val)) {
        if (!JS_IsArray(ctx, args_val))
            return JS_ThrowInternalError(ctx, "args must be an array");
        {
            JSValue lv = JS_GetPropertyStr(ctx, args_val, "length");
            uint32_t lu = 0;
            JS_ToUint32(ctx, &lu, lv);
            JS_FreeValue(ctx, lv);
            argc = (int)lu;
        }
        if (argc != n)
            return JS_ThrowInternalError(ctx, "expected %d args, got %d",
                                         n, argc);
    } else if (n != 0) {
        return JS_ThrowInternalError(ctx, "expected %d args", n);
    }
    for (i = 0; i < n; i++) {
        el = JS_GetPropertyUint32(ctx, args_val, (uint32_t)i);
        if (green_java_arg_to_jval(ctx, env, argt[i], el, &jv[i]) != 0) {
            JS_FreeValue(ctx, el);
            return JS_ThrowInternalError(ctx,
                "cannot marshal arg %d as '%c'", i, argt[i]);
        }
        JS_FreeValue(ctx, el);
    }
    (*env)->ExceptionClear(env);

    if (is_ctor) {
        jobject o = (*env)->NewObjectA(env,
            (jclass)green_jobj_get(cls_id), (jmethodID)(uintptr_t)mid_raw,
            jv);
        if (o == NULL) {
            (*env)->ExceptionClear(env);
            return JS_ThrowInternalError(ctx, "NewObject failed");
        }
        {
            JSValue r = JS_NewInt32(ctx, green_jobj_put(env, o));
            (*env)->DeleteLocalRef(env, o);
            return r;
        }
    }
    if (is_static) {
        jclass cls = (jclass)green_jobj_get(cls_id);
        jvalue v = { 0 };
        switch (ret) {
        case 'V': (*env)->CallStaticVoidMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'L': case '[': v.l = (*env)->CallStaticObjectMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'J': v.j = (*env)->CallStaticLongMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'F': v.f = (*env)->CallStaticFloatMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'D': v.d = (*env)->CallStaticDoubleMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        default: v.i = (*env)->CallStaticIntMethodA(env, cls,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            return JS_ThrowInternalError(ctx, "static call threw");
        }
        return green_java_ret_wrap(ctx, env, ret, v);
    } else {
        jobject obj = green_jobj_get(obj_id);
        jvalue v = { 0 };
        if (obj == NULL)
            return JS_ThrowInternalError(ctx, "null receiver");
        switch (ret) {
        case 'V': (*env)->CallVoidMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'L': case '[': v.l = (*env)->CallObjectMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'J': v.j = (*env)->CallLongMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'F': v.f = (*env)->CallFloatMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        case 'D': v.d = (*env)->CallDoubleMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        default: v.i = (*env)->CallIntMethodA(env, obj,
            (jmethodID)(uintptr_t)mid_raw, jv); break;
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            return JS_ThrowInternalError(ctx, "method call threw");
        }
        return green_java_ret_wrap(ctx, env, ret, v);
    }
}

/* __green_java_call(clsId, objId, mid, sig, isStatic, args[]) */
static JSValue js_java_call(JSContext *ctx, JSValueConst this_val,
                            int argc, JSValueConst *argv)
{
    JNIEnv *env;
    int cls_id = 0, obj_id = 0, is_static = 0;
    int64_t mid = 0;
    const char *sig;

    (void)this_val;
    if (argc < 6 || (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "java_call(...)");
    JS_ToInt32(ctx, &cls_id, argv[0]);
    JS_ToInt32(ctx, &obj_id, argv[1]);
    JS_ToInt64(ctx, &mid, argv[2]);
    sig = JS_ToCString(ctx, argv[3]);
    JS_ToInt32(ctx, &is_static, argv[4]);
    if (sig == NULL || mid == 0)
        return JS_ThrowInternalError(ctx, "bad call args");
    return green_java_do_call(ctx, env, cls_id, obj_id, mid, sig, argv[5],
                              is_static, 0);
}

/* __green_java_new_object(clsId, ctorMid, sig, args[]) -> objId */
static JSValue js_java_new_object(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    JNIEnv *env;
    int cls_id = 0;
    int64_t mid = 0;
    const char *sig;

    (void)this_val;
    if (argc < 4 || (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "new_object(...)");
    JS_ToInt32(ctx, &cls_id, argv[0]);
    JS_ToInt64(ctx, &mid, argv[1]);
    sig = JS_ToCString(ctx, argv[2]);
    if (sig == NULL || mid == 0)
        return JS_ThrowInternalError(ctx, "bad ctor args");
    return green_java_do_call(ctx, env, cls_id, 0, mid, sig, argv[3], 0, 1);
}

/* __green_java_hook(clsId, mid, name, sig, isStatic, fn) -> ok */
static JSValue js_java_hook(JSContext *ctx, JSValueConst this_val,
                            int argc, JSValueConst *argv)
{
    JNIEnv *env;
    int cls_id = 0, is_static = 0, idx;
    int64_t mid = 0;
    const char *name, *sig;
    GreenJavaHook *h;
    char args[24];
    char ret = 'V';
    int n;

    {
        static int hlog = 0;
        if (hlog < 6) {
            const char *nn = argc > 2 ? JS_ToCString(ctx, argv[2]) : "?";
            const char *ss = argc > 3 ? JS_ToCString(ctx, argv[3]) : "?";
            __android_log_print(ANDROID_LOG_ERROR, "green-java",
                "hook req: argc=%d name=%s sig=%s", argc, nn ? nn : "?",
                ss ? ss : "?");
            if (nn) JS_FreeCString(ctx, nn);
            if (ss) JS_FreeCString(ctx, ss);
            hlog++;
        }
    }
    (void)this_val;
    if (argc < 6 || !JS_IsFunction(ctx, argv[5]) ||
        (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "java_hook(cls,mid,name,sig,st,fn)");
    if (green_java_calibrate() != 0)
        return JS_ThrowInternalError(ctx, "ArtMethod calibration failed");

    JS_ToInt32(ctx, &cls_id, argv[0]);
    JS_ToInt64(ctx, &mid, argv[1]);
    name = JS_ToCString(ctx, argv[2]);
    sig = JS_ToCString(ctx, argv[3]);
    JS_ToInt32(ctx, &is_static, argv[4]);
    if (name == NULL || sig == NULL || mid == 0) {
        if (name) JS_FreeCString(ctx, name);
        if (sig) JS_FreeCString(ctx, sig);
        return JS_ThrowInternalError(ctx, "bad hook args");
    }
    n = green_java_parse_sig(sig, args, (int)sizeof(args), &ret);
    if (n < 0) {
        JS_FreeCString(ctx, name);
        JS_FreeCString(ctx, sig);
        return JS_ThrowInternalError(ctx, "bad signature %s", sig);
    }
    if (n > 6) {
        JS_FreeCString(ctx, name);
        JS_FreeCString(ctx, sig);
        return JS_ThrowInternalError(ctx,
                                     "hook supports at most 6 arguments");
    }

    for (idx = 0; idx < GREEN_MAX_JHOOK; idx++)
        if (!g_jhook[idx].used)
            break;
    if (idx == GREEN_MAX_JHOOK) {
        JS_FreeCString(ctx, name);
        JS_FreeCString(ctx, sig);
        return JS_ThrowInternalError(ctx, "too many hooks");
    }

    h = &g_jhook[idx];
    if (h->backup == NULL)
        h->backup = malloc((size_t)g_am_size);
    if (h->backup == NULL)
        goto fail;
    memcpy(h->backup, (void *)(uintptr_t)mid, (size_t)g_am_size);
    if (green_java_make_thunk(idx, &h->thunk) != 0)
        goto fail;

    {
        volatile void **o_jni = (volatile void **)((uint8_t *)(uintptr_t)mid
                                                   + g_am_jni_off);
        volatile void **o_quick = (volatile void **)((uint8_t *)(uintptr_t)mid
                                                      + g_am_quick_off);
        volatile uint32_t *o_flags = (volatile uint32_t *)((uint8_t *)
            (uintptr_t)mid + 4);
        LOGI("pre-patch mid=%p flags=%08x jni=%p quick=%p (backup copy at %p)",
             (void *)(uintptr_t)mid, *o_flags, *o_jni, *o_quick,
             (void *)h->backup);
        LOGI("post-copy backup: jni=%p quick=%p",
             *(void **)(h->backup + g_am_jni_off),
             *(void **)(h->backup + g_am_quick_off));
    }
    h->orig_mid = (uint8_t *)(uintptr_t)mid;
    h->orig_quick = *(void **)(h->backup + g_am_quick_off);
    __android_log_print(ANDROID_LOG_ERROR, "green-java",
        "backup dump: flags=%08x jni=%p quick=%p (orig mid=%p)",
        *(uint32_t *)(h->backup + 4),
        *(void **)(h->backup + g_am_jni_off),
        *(void **)(h->backup + g_am_quick_off),
        (void *)mid);
    h->cls = (jclass)green_jobj_get(cls_id);
    h->name = strdup(name);
    h->sig = strdup(sig);
    h->ret = ret;
    memcpy(h->args, args, (size_t)n);
    h->nargs = n;
    h->is_static = is_static;
    h->fn = JS_DupValue(ctx, argv[5]);
    h->used = 1;

    /* Patch the live ArtMethod (LinearAlloc pages are RW in-process). */
    {
        volatile uint32_t *flags =
            (volatile uint32_t *)(h->orig_mid + 4);
        volatile void **jni_slot =
            (volatile void **)(h->orig_mid + g_am_jni_off);
        volatile void **quick_slot =
            (volatile void **)(h->orig_mid + g_am_quick_off);
        *flags = *flags | GREEN_KNATIVE;
        *jni_slot = (void *)h->thunk;
        *quick_slot = g_generic_jni_trampoline;
        __asm__ volatile("dsb sy; isb" ::: "memory");
        LOGI("patched %s: mid=%p flags=%08x jni_slot=%p->%p "
             "quick_slot=%p->%p (want thunk=%p tramp=%p)",
             h->name, h->orig_mid, *flags, (void *)jni_slot,
             (void *)*jni_slot, (void *)quick_slot, (void *)*quick_slot,
             h->thunk, g_generic_jni_trampoline);
    }

    JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, sig);
    LOGI(
        "hooked %s.%s%s (idx=%d quick=+%d jni=+%d)",
        h->cls ? "class" : "?", h->name, is_static ? " [static]" : "",
        idx, g_am_quick_off, g_am_jni_off);
    return JS_NewInt32(ctx, idx + 1);
fail:
    JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, sig);
    h->used = 0;
    return JS_ThrowInternalError(ctx, "hook setup failed");
}

/* __green_java_call_backup(args[]) — invokes the original method via the
 * ART quick calling convention: x7 = backup ArtMethod, x1 = receiver,
 * x2.. = java args (x0 is reserved by quick code).  This bypasses
 * jmethodID indirection entirely and works for AOT-compiled, interpreted
 * and native methods alike (verified against String.hashCode AOT code:
 * +0x10 LDR W0,[X1,#0xc] reads the receiver from x1). */
extern int64_t green_call_asm(const void *fn, const int64_t *args,
                              int nargs);

static JSValue js_java_call_backup(JSContext *ctx, JSValueConst this_val,
                                   int argc, JSValueConst *argv)
{
    GreenJCtx *c;
    GreenJavaHook *h;
    JNIEnv *env;
    jvalue jv[24];
    int i, n;

    (void)this_val; (void)argc;
    if (g_jctx_sp <= 0)
        return JS_ThrowInternalError(ctx, "no active hook on this thread");
    c = &g_jctx[g_jctx_sp - 1];
    env = c->env;
    h = &g_jhook[c->hook_idx];

    n = h->nargs;
    for (i = 0; i < n && i < 24; i++) {
        JSValue el = JS_GetPropertyUint32(ctx, argv[0], (uint32_t)i);
        char t = h->args[i];
        if (t == 'L' || t == '[') {
            if (JS_IsString(el)) {
                const char *sv = JS_ToCString(ctx, el);
                jv[i].l = sv ? (*env)->NewStringUTF(env, sv) : NULL;
                if (sv)
                    JS_FreeCString(ctx, sv);
            } else if (JS_IsNumber(el)) {
                int32_t id = 0;
                JS_ToInt32(ctx, &id, el);
                jv[i].l = green_jobj_get(id);
            } else if (JS_IsObject(el)) {
                JSValue idv = JS_GetPropertyStr(ctx, el, "__greenobj");
                int32_t id = 0;
                JS_ToInt32(ctx, &id, idv);
                JS_FreeValue(ctx, idv);
                jv[i].l = green_jobj_get(id);
            } else {
                jv[i].l = NULL;
            }
        } else if (t == 'J') {
            int64_t v = 0;
            JS_ToInt64(ctx, &v, el);
            jv[i].j = v;
        } else {
            int64_t v = 0;
            JS_ToInt64(ctx, &v, el);
            jv[i].i = (int32_t)v;
        }
        JS_FreeValue(ctx, el);
    }

    /* Invoke the backup ArtMethod through JNI.  The backup carries the
     * ORIGINAL flags/entrypoints, so this cannot re-enter the hook. */
    {
        jmethodID bm = (jmethodID)(void *)c->backup;
        jvalue v = { 0 };
        if (h->is_static) {
            switch (c->ret) {
            case 'V': (*env)->CallStaticVoidMethodA(env, c->cls, bm, jv); break;
            case 'L': case '[': v.l = (*env)->CallStaticObjectMethodA(env,
                c->cls, bm, jv); break;
            case 'J': v.j = (*env)->CallStaticLongMethodA(env, c->cls,
                bm, jv); break;
            case 'F': v.f = (*env)->CallStaticFloatMethodA(env, c->cls,
                bm, jv); break;
            case 'D': v.d = (*env)->CallStaticDoubleMethodA(env, c->cls,
                bm, jv); break;
            default: v.i = (*env)->CallStaticIntMethodA(env, c->cls,
                bm, jv); break;
            }
        } else {
            switch (c->ret) {
            case 'V': (*env)->CallVoidMethodA(env, c->recv, bm, jv); break;
            case 'L': case '[': v.l = (*env)->CallObjectMethodA(env,
                c->recv, bm, jv); break;
            case 'J': v.j = (*env)->CallLongMethodA(env, c->recv, bm, jv); break;
            case 'F': v.f = (*env)->CallFloatMethodA(env, c->recv, bm, jv); break;
            case 'D': v.d = (*env)->CallDoubleMethodA(env, c->recv, bm, jv); break;
            default: v.i = (*env)->CallIntMethodA(env, c->recv, bm, jv); break;
            }
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            return JS_ThrowInternalError(ctx, "original call threw");
        }
        return green_java_ret_wrap(ctx, env, c->ret, v);
    }
}


/* __green_java_to_string(objId) -> string */
static JSValue js_java_to_string(JSContext *ctx, JSValueConst this_val,
                                 int argc, JSValueConst *argv)
{
    JNIEnv *env;
    jobject obj;
    jclass k_obj;
    jmethodID m_ts;
    jstring s;
    const char *u;
    JSValue r;
    int id = 0;

    (void)this_val;
    if (argc < 1 || (env = green_jni_env()) == NULL)
        return JS_ThrowInternalError(ctx, "to_string(objId)");
    JS_ToInt32(ctx, &id, argv[0]);
    obj = green_jobj_get(id);
    if (obj == NULL)
        return JS_NewString(ctx, "null");
    k_obj = (*env)->FindClass(env, "java/lang/Object");
    m_ts = (*env)->GetMethodID(env, k_obj, "toString",
                               "()Ljava/lang/String;");
    s = (*env)->CallObjectMethod(env, obj, m_ts);
    if (s == NULL) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, k_obj);
        return JS_NewString(ctx, "<toString failed>");
    }
    u = (*env)->GetStringUTFChars(env, s, NULL);
    r = u ? JS_NewString(ctx, u) : JS_NewString(ctx, "?");
    if (u)
        (*env)->ReleaseStringUTFChars(env, s, u);
    (*env)->DeleteLocalRef(env, s);
    (*env)->DeleteLocalRef(env, k_obj);
    return r;
}

/* __green_java_delete_ref(objId) */
static JSValue js_java_delete_ref(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    JNIEnv *env;
    int id = 0;

    (void)this_val;
    if (argc < 1 || (env = green_jni_env()) == NULL)
        return JS_UNDEFINED;
    JS_ToInt32(ctx, &id, argv[0]);
    if (id > 0 && id <= GREEN_MAX_JOBJ && g_jobj[id - 1] != NULL) {
        (*env)->DeleteGlobalRef(env, g_jobj[id - 1]);
        g_jobj[id - 1] = NULL;
    }
    return JS_UNDEFINED;
}

/* Registration entry called from js_ensure_runtime. */
__attribute__((visibility("default")))
void green_java_register_natives(JSContext *ctx, JSValue global)
{
    JS_SetPropertyStr(ctx, global, "__green_java_available",
        JS_NewCFunction(ctx, js_java_available,
                        "__green_java_available", 0));
    JS_SetPropertyStr(ctx, global, "__green_java_find_class",
        JS_NewCFunction(ctx, js_java_find_class,
                        "__green_java_find_class", 1));
    JS_SetPropertyStr(ctx, global, "__green_java_class_info",
        JS_NewCFunction(ctx, js_java_class_info,
                        "__green_java_class_info", 1));
    JS_SetPropertyStr(ctx, global, "__green_java_get_method_id",
        JS_NewCFunction(ctx, js_java_get_method_id,
                        "__green_java_get_method_id", 4));
    JS_SetPropertyStr(ctx, global, "__green_java_call",
        JS_NewCFunction(ctx, js_java_call, "__green_java_call", 6));
    JS_SetPropertyStr(ctx, global, "__green_java_new_object",
        JS_NewCFunction(ctx, js_java_new_object,
                        "__green_java_new_object", 4));
    JS_SetPropertyStr(ctx, global, "__green_java_hook",
        JS_NewCFunction(ctx, js_java_hook, "__green_java_hook", 6));
    JS_SetPropertyStr(ctx, global, "__green_java_call_backup",
        JS_NewCFunction(ctx, js_java_call_backup,
                        "__green_java_call_backup", 1));
    JS_SetPropertyStr(ctx, global, "__green_java_to_string",
        JS_NewCFunction(ctx, js_java_to_string,
                        "__green_java_to_string", 1));
    JS_SetPropertyStr(ctx, global, "__green_java_delete_ref",
        JS_NewCFunction(ctx, js_java_delete_ref,
                        "__green_java_delete_ref", 1));
}
