/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * green_hook end-to-end test (root, on device, with the green KPM loaded).
 *
 * The hook redirect is emitted by the VENDORED frida-gum GumArm64Writer
 * (vendor/gum/arch-arm64/gumarm64writer.c) and committed through
 * gum_memory_patch_code() whose backend (hook/gummemory-green.c) writes via
 * the green shadow pager — no mprotect, no hand-encoded instructions.
 *
 * Verifies gum hook-time semantics on a live RX page:
 *   1. patch: execution of target_fn() takes the writer-emitted redirect;
 *   2. read:  GUP (process_vm_readv) and direct reads still observe the
 *             ORIGINAL bytes while the hook is active;
 *   3. restore: green_gum_release_page() brings target_fn() back.
 */

#include <gum/arch-arm64/gumarm64writer.h>
#include <gum/gummemory.h>

#include "green_gum.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <green/abi.h>

#define PATCH_LEN 16U

__attribute__((noinline, aligned(4096))) static int target_fn(int x)
{
    asm volatile("" ::: "memory");
    return x + 1;
}

__attribute__((noinline, aligned(4096))) static int replacement_fn(int x)
{
    asm volatile("" ::: "memory");
    return x + 100;
}

__attribute__((noinline, aligned(4096))) static void target_pad(void)
{
    asm volatile(".space 64" ::: "memory");
}

/*
 * gum: apply callback used with gum_memory_patch_code(), mirroring
 * _gum_interceptor_backend_activate_trampoline() — the real GumArm64Writer
 * emits LDR x16, <literal>; BR x16 and appends the literal pool itself.
 */
static void apply_redirect(void *mem, void *user_data)
{
    GumArm64Writer writer;
    guint64 replacement = (guint64)(uintptr_t)user_data;

    gum_arm64_writer_init(&writer, mem);
    writer.pc = (GumAddress)(uintptr_t)mem;

    gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16, replacement);
    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);
}

static ssize_t gup_read_self(void *dst, const void *remote, size_t len)
{
    struct iovec local = { .iov_base = dst, .iov_len = len };
    struct iovec src = { .iov_base = (void *)remote, .iov_len = len };
    ssize_t n;

    do {
        n = process_vm_readv(getpid(), &local, 1, &src, 1, 0);
    } while (n < 0 && errno == EINTR);
    return n;
}

/* byte-wise volatile read (ldrb): always supported by the same-page emu */
static __attribute__((noinline)) void direct_read(uint8_t *dst, const volatile uint8_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dst[i] = src[i];
}

/*
 * Kernel uaccess read: write() -> copy_from_user reads the page while it is
 * in the EXEC state.  On EPAN hardware PAN blocks this (EFAULT); without
 * EPAN the read succeeds and observes whatever the PTE maps — the leak the
 * hard requirement guards against.
 */
static ssize_t uaccess_read(uint8_t *dst, const void *src, size_t len)
{
    int fds[2];
    ssize_t n;

    if (pipe(fds) != 0)
        return -1;
    n = write(fds[1], src, len);
    if (n > 0) {
        ssize_t got = read(fds[0], dst, (size_t)n);
        (void)got;
    }
    close(fds[0]);
    close(fds[1]);
    return n;
}

static int failures;

#define CHECK(cond, msg)                     \
    do {                                     \
        if (cond) {                          \
            printf("  ok   %s\n", msg);      \
        } else {                             \
            printf("  FAIL %s\n", msg);      \
            failures++;                      \
        }                                    \
    } while (0)

int main(void)
{
    uint8_t before[PATCH_LEN];
    uint8_t during[PATCH_LEN];
    long shadow_pages;
    int value;

    (void)target_pad;

    printf("green_hook test (gum sources + shadow backend)\n");
    printf("  target=%p replacement=%p writer=%s\n", (void *)target_fn,
           (void *)replacement_fn, "GumArm64Writer");

    /* --- baseline ------------------------------------------------------ */

    value = target_fn(1);
    CHECK(value == 2, "target_fn(1) == 2 before patch");

    direct_read(before, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(gup_read_self(during, target_fn, PATCH_LEN) == (ssize_t)PATCH_LEN,
          "baseline GUP read");

    /* --- install hook: gum writer + gum patch API + shadow backend ------ */

    CHECK(gum_memory_patch_code((void *)target_fn, PATCH_LEN, apply_redirect,
                                (void *)(uintptr_t)replacement_fn),
          "gum_memory_patch_code() installs writer-emitted redirect");

    shadow_pages = prctl((int)PR_GREEN_SHADOW_COUNT, 0, 0, 0, 0);
    CHECK(shadow_pages >= 1, "shadow page is live");

    /* --- execution sees the patch --------------------------------------- */

    value = target_fn(1);
    CHECK(value == 101, "target_fn(1) == 101 while hooked");

    value = target_fn(41);
    CHECK(value == 141, "target_fn(41) == 141 while hooked");

    /* --- reads while hooked ---------------------------------------------- */

    /* GUP readers (process_vm_readv, ptrace, /proc/pid/mem) get the original
     * page through the follow_page_pte hook. */
    CHECK(gup_read_self(during, target_fn, PATCH_LEN) == (ssize_t)PATCH_LEN,
          "GUP read succeeds while hooked");
    CHECK(memcmp(before, during, PATCH_LEN) == 0,
          "GUP read sees ORIGINAL bytes while hooked");

    /* Execute-only exec view (AP=10 + UXN=0): a direct load from test code
     * (different page) takes a read fault, the seesaw switches the page to
     * the r-- original view, and the load observes the ORIGINAL bytes. */
    direct_read(during, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(memcmp(before, during, PATCH_LEN) == 0,
          "direct read sees ORIGINAL bytes while hooked (read-fault seesaw)");

    /* also via the gum API itself */
    {
        gsize n = 0;
        guint8 *bytes = gum_memory_read(target_fn, PATCH_LEN, &n);

        CHECK(bytes != NULL && n == PATCH_LEN, "gum_memory_read() works");
        CHECK(bytes != NULL && memcmp(before, bytes, PATCH_LEN) == 0,
              "gum_memory_read() sees ORIGINAL bytes (GUP path)");
        g_free(bytes);
    }

    /* --- kernel uaccess read while in EXEC state ----------------------- */

    value = target_fn(1); /* leave the page in the EXEC (execute-only) view */
    (void)value;
    {
        ssize_t n = uaccess_read(during, target_fn, PATCH_LEN);

        if (n < 0) {
            printf("  info uaccess read faulted errno=%d (EPAN/PAN blocked)\n",
                   errno);
        } else {
            printf("  info uaccess read got %zd bytes: ", n);
            for (size_t i = 0; i < (size_t)n && i < PATCH_LEN; i++)
                printf("%02x ", during[i]);
            printf("\n         expected original: ");
            for (size_t i = 0; i < PATCH_LEN; i++)
                printf("%02x ", before[i]);
            printf("\n");
            if (memcmp(before, during, (size_t)n) == 0) {
                printf("  info uaccess read sees ORIGINAL (no leak)\n");
            } else {
                printf("  LEAK uaccess read sees SHADOW bytes without EPAN\n");
            }
        }
    }

    /* --- restore --------------------------------------------------------- */

    CHECK(green_gum_release_page(target_fn), "green_gum_release_page()");

    value = target_fn(1);
    CHECK(value == 2, "target_fn(1) == 2 after release");

    direct_read(during, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(memcmp(before, during, PATCH_LEN) == 0,
          "direct read unchanged after release");

    printf(failures == 0 ? "green_hook test: ALL PASS\n"
                         : "green_hook test: FAILURES=%d\n",
           failures);
    return failures == 0 ? 0 : 1;
}
