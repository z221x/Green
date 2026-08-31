/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal glib shim for the vendored frida-gum sources used by green_hook.
 *
 * Only the primitives used by gum/{gumdefs.h, gumlibc.c, gummetalarray.c,
 * gummetalhash.c, arch-arm64/gumarm64writer.c} are provided:
 *   - scalar types and declarative macros
 *   - g_slice_*            -> malloc/free
 *   - g_atomic_int_*       -> GCC atomics
 *   - g_assert*            -> abort
 *   - g_newa               -> alloca
 * Opaque container types (GArray, GPtrArray, ...) exist only so that the
 * vendored prototypes parse; green_hook never instantiates them.
 */

#ifndef _GREEN_GLIB_SHIM_H_
#define _GREEN_GLIB_SHIM_H_

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define G_BEGIN_DECLS
#define G_END_DECLS

typedef int gboolean;
typedef char gchar;
typedef unsigned char guchar;
typedef signed char gint8;
typedef unsigned char guint8;
typedef short gint16;
typedef unsigned short guint16;
typedef int gint;
typedef unsigned int guint;
typedef long glong;
typedef unsigned long gulong;
typedef long long gint64;
typedef unsigned long long guint64;
typedef size_t gsize;
typedef ptrdiff_t gssize;
typedef void *gpointer;
typedef const void *gconstpointer;
typedef gint gint32;
typedef guint guint32;
typedef uintptr_t guintptr;
typedef intptr_t gintptr;
typedef guint32 GQuark;
typedef double gdouble;
typedef float gfloat;

typedef struct _GArray GArray;
typedef struct _GPtrArray GPtrArray;
typedef struct _GHashTable GHashTable;
typedef struct _GRegex GRegex;
typedef struct _GMatchInfo GMatchInfo;
typedef struct _GThreadPool GThreadPool;
typedef gsize GType;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define G_GNUC_INTERNAL __attribute__ ((visibility ("hidden")))
#define G_GNUC_CONST __attribute__ ((const))
#define G_GNUC_UNUSED __attribute__ ((unused))
#define G_GNUC_MALLOC __attribute__ ((malloc))
#define G_GNUC_NORETURN __attribute__ ((noreturn))
#define G_NORETURN __attribute__ ((noreturn))
#define G_ANALYZER_NORETURN
#define G_GINT64_CONSTANT(x) (x##LL)
#define G_GUINT64_CONSTANT(x) (x##ULL)
#define G_MAXINT32 ((gint32) 0x7fffffff)
#define G_MININT32 ((gint32) (-G_MAXINT32 - 1))
#define G_STRUCT_OFFSET(type, member) offsetof (type, member)
#define G_N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))
#define G_LITTLE_ENDIAN 1234
#define G_BIG_ENDIAN 4321
#define G_BYTE_ORDER G_LITTLE_ENDIAN
#define G_OS_UNIX 1

#define g_slice_new(type) ((type *) g_slice_alloc (sizeof (type)))
#define g_slice_new0(type) ((type *) g_slice_alloc0 (sizeof (type)))
#define g_slice_dup(type, mem) \
    ((type *) g_slice_copy (sizeof (type), (mem)))
#define g_slice_free(type, mem) g_free (mem)
#define g_slice_alloc(size) g_malloc (size)
#define g_slice_alloc0(size) g_malloc0 (size)
#define g_slice_copy(size, mem) g_memdup (mem, size)
#define g_newa(type, n) ((type *) __builtin_alloca (sizeof (type) * (n)))

static inline void g_free (gpointer mem)
{
    free (mem);
}

static inline gpointer g_malloc (gsize size)
{
    gpointer mem = malloc (size);
    if (mem == NULL)
        abort ();
    return mem;
}

static inline gpointer g_malloc0 (gsize size)
{
    gpointer mem = calloc (1, size);
    if (mem == NULL)
        abort ();
    return mem;
}

static inline gpointer g_realloc (gpointer mem, gsize size)
{
    gpointer new_mem = realloc (mem, size);
    if (new_mem == NULL)
        abort ();
    return new_mem;
}

static inline gpointer g_memdup (gconstpointer mem, gsize byte_size)
{
    gpointer dup;

    if (mem == NULL)
        return NULL;
    dup = g_malloc (byte_size);
    memcpy (dup, mem, byte_size);
    return dup;
}

static inline gpointer g_strdup (const gchar * str)
{
    gsize n;

    if (str == NULL)
        return NULL;
    n = strlen (str) + 1;
    return memcpy (g_malloc (n), str, n);
}

static inline void g_atomic_int_inc (volatile gint * atomic)
{
    __atomic_add_fetch (atomic, 1, __ATOMIC_SEQ_CST);
}

static inline gboolean g_atomic_int_dec_and_test (volatile gint * atomic)
{
    return __atomic_sub_fetch (atomic, 1, __ATOMIC_SEQ_CST) == 0;
}

static inline gint g_atomic_int_get (volatile gint * atomic)
{
    return __atomic_load_n (atomic, __ATOMIC_SEQ_CST);
}

G_GNUC_NORETURN static inline void g_assertion_message_abort (void)
{
    abort ();
}

#define g_assert(expr) \
    do { \
        if (!(expr)) \
            g_assertion_message_abort (); \
    } while (0)
#define g_assert_not_reached() g_assertion_message_abort ()
#define g_abort() abort ()

typedef gint (*GCompareFunc) (gconstpointer a, gconstpointer b);
typedef void (*GDestroyNotify) (gpointer data);
typedef guint (*GHashFunc) (gconstpointer key);
typedef gboolean (*GEqualFunc) (gconstpointer a, gconstpointer b);
typedef void (*GHFunc) (gpointer key, gpointer value, gpointer user_data);
typedef gboolean (*GHRFunc) (gpointer key, gpointer value, gpointer user_data);

#define GINT_TO_POINTER(i) ((gpointer) (glong) (i))
#define GPOINTER_TO_INT(p) ((gint) (glong) (p))
#define GPOINTER_TO_UINT(p) ((guint) (gulong) (p))
#define GUINT_TO_POINTER(u) ((gpointer) (gulong) (u))
#define GSIZE_TO_POINTER(s) ((gpointer) (gsize) (s))
#define GPOINTER_TO_SIZE(p) ((gsize) (p))

/* byte-order macros: Android ARM64 is little-endian */
#define GUINT16_TO_LE(v) ((guint16) (v))
#define GUINT16_FROM_LE(v) GUINT16_TO_LE (v)
#define GUINT32_TO_LE(v) ((guint32) (v))
#define GUINT32_FROM_LE(v) GUINT32_TO_LE (v)
#define GUINT64_TO_LE(v) ((guint64) (v))
#define GUINT64_FROM_LE(v) GUINT64_TO_LE (v)
#define GINT32_TO_LE(v) ((gint32) (v))
#define GINT32_FROM_LE(v) GINT32_TO_LE (v)
#define GINT64_TO_LE(v) ((gint64) (v))
#define GINT64_FROM_LE(v) GINT64_TO_LE (v)
#define GUINT32_TO_BE(v) __builtin_bswap32 (v)
#define GUINT32_FROM_BE(v) GUINT32_TO_BE (v)
#define GUINT64_TO_BE(v) __builtin_bswap64 (v)
#define GUINT64_FROM_BE(v) GUINT64_TO_BE (v)
#define GINT32_TO_BE(v) ((gint32) GUINT32_TO_BE ((guint32) (v)))
#define GINT32_FROM_BE(v) GINT32_TO_BE (v)
#define GINT64_TO_BE(v) ((gint64) GUINT64_TO_BE ((guint64) (v)))
#define GINT64_FROM_BE(v) GINT64_TO_BE (v)
#define GUM_UNUSED G_GNUC_UNUSED

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#define G_UNLIKELY(expr) (__builtin_expect ((expr) != 0, 0))
#define G_LIKELY(expr) (__builtin_expect ((expr) != 0, 1))

static inline guint g_direct_hash (gconstpointer v)
{
    return GPOINTER_TO_UINT (v);
}

#define g_return_if_fail(expr) \
    do { if (!(expr)) return; } while (0)
#define g_return_val_if_fail(expr, val) \
    do { if (!(expr)) return (val); } while (0)

#endif /* _GREEN_GLIB_SHIM_H_ */
