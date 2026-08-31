/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * green_hook end-to-end test (runs as root on the device with the green KPM
 * loaded).
 *
 * Verifies the three core gum-semantics guarantees on a live RX page:
 *
 *   1. patch  — execution of target_fn() observes the redirect written via
 *               green_gum_memory_patch_code();
 *   2. read   — both direct (same-process, cross-page) reads and GUP
 *               (process_vm_readv) reads still observe the ORIGINAL bytes
 *               while the hook is active;
 *   3. restore— green_gum_release_page() brings target_fn() back.
 */

#include <green/gum_io.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <unistd.h>

#include <green/abi.h>

#define PATCH_LEN 16U

/*
 * Keep these out of the compiler's reach for inlining and make sure both sit
 * on pages distinct from the test code (separate function, aligned).
 */
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

/* padding so target_fn is at least PATCH_LEN bytes before the next symbol */
__attribute__((noinline, aligned(4096))) static void target_pad(void)
{
    asm volatile(".space 64" ::: "memory");
}

struct patch_ctx {
    uint64_t pc;
    uint64_t replacement;
};

static void apply_redirect(void *mem, void *user_data)
{
    struct patch_ctx *ctx = user_data;

    /* gum: _gum_interceptor_backend_activate_trampoline() equivalent. */
    green_hook_write_branch_ldr((uint32_t *)mem, ctx->replacement);
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

static long prctl_green_count(void)
{
    return prctl((int)PR_GREEN_SHADOW_COUNT, 0, 0, 0, 0);
}

/* byte-wise volatile read: ldrb, always supported by the same-page emu */
static void direct_read(uint8_t *dst, const volatile uint8_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dst[i] = src[i];
}

static int failures;

#define CHECK(cond, msg)                                          \
    do {                                                          \
        if (cond) {                                               \
            printf("  ok   %s\n", msg);                           \
        } else {                                                  \
            printf("  FAIL %s\n", msg);                           \
            failures++;                                           \
        }                                                         \
    } while (0)

int main(void)
{
    uint8_t before[PATCH_LEN];
    uint8_t during_gup[PATCH_LEN];
    uint8_t during_direct[PATCH_LEN];
    struct patch_ctx ctx;
    long shadow_pages;
    int value;

    (void)target_pad;

    printf("green_hook test: target=%p replacement=%p\n", (void *)target_fn,
           (void *)replacement_fn);

    /* --- baseline ------------------------------------------------------ */

    value = target_fn(1);
    CHECK(value == 2, "target_fn(1) == 2 before patch");

    direct_read(before, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(gup_read_self(during_gup, target_fn, PATCH_LEN) == (ssize_t)PATCH_LEN,
          "baseline GUP read");

    /* --- install hook via the gum-compatible patch API ------------------ */

    ctx.pc = (uint64_t)(uintptr_t)target_fn;
    ctx.replacement = (uint64_t)(uintptr_t)replacement_fn;

    CHECK(green_gum_memory_patch_code((void *)target_fn, PATCH_LEN,
                                      apply_redirect, &ctx) == 0,
          "green_gum_memory_patch_code() installs redirect");

    shadow_pages = prctl_green_count();
    CHECK(shadow_pages >= 1, "shadow page is live");

    /* --- execution sees the patch --------------------------------------- */

    value = target_fn(1);
    CHECK(value == 101, "target_fn(1) == 101 while hooked (redirect taken)");

    value = target_fn(41);
    CHECK(value == 141, "target_fn(41) == 141 while hooked");

    /* --- reads still see the original bytes ------------------------------ */

    CHECK(gup_read_self(during_gup, target_fn, PATCH_LEN) ==
              (ssize_t)PATCH_LEN,
          "GUP read succeeds while hooked");
    CHECK(memcmp(before, during_gup, PATCH_LEN) == 0,
          "GUP read sees ORIGINAL bytes while hooked");

    /*
     * The literal load inside the redirect (ldr x16,#8) executes on the
     * shadow page and reads the shadow literal — proven by the redirect
     * working above.  A direct read from THIS page (test code lives on a
     * different page) must fault-switch to the original mapping instead.
     */
    direct_read(during_direct, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(memcmp(before, during_direct, PATCH_LEN) == 0,
          "direct read sees ORIGINAL bytes while hooked");

    /* --- restore --------------------------------------------------------- */

    CHECK(green_gum_release_page(target_fn) == 0, "release shadow page");

    value = target_fn(1);
    CHECK(value == 2, "target_fn(1) == 2 after release");

    direct_read(during_direct, (const volatile uint8_t *)target_fn, PATCH_LEN);
    CHECK(memcmp(before, during_direct, PATCH_LEN) == 0,
          "direct read unchanged after release");

    printf(failures == 0 ? "green_hook test: ALL PASS\n"
                         : "green_hook test: FAILURES=%d\n",
           failures);
    return failures == 0 ? 0 : 1;
}
