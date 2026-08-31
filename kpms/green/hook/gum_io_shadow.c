/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * green_hook memory I/O — frida-gum gummemory layer reimplemented on top of
 * the green shadow pager.
 *
 * Mapping (see IO_MAP.md):
 *   gum_memory_patch_code[_pages]  -> prctl(PR_GREEN_SHADOW_PATCH)
 *   gum_memory_write (code pages)  -> prctl(PR_GREEN_SHADOW_PATCH)
 *   gum_memory_read                -> process_vm_readv (GUP hook serves the
 *                                     original PFN for shadowed pages)
 *   gum_mprotect                   -> native mprotect (gum's own allocations)
 *   gum_clear_cache                -> no-op (kernel syncs at patch time)
 */

#include <green/gum_io.h>
#include <green/abi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <unistd.h>

static long green_gum_shadow_prctl(unsigned long option, unsigned long a2,
                                   unsigned long a3, unsigned long a4,
                                   unsigned long a5)
{
    long ret;

    errno = 0;
    ret = prctl((int)option, a2, a3, a4, a5);
    if (ret < 0)
        return errno ? -errno : ret;
    return ret;
}

uint8_t *green_gum_memory_read(const void *address, size_t len,
                               size_t *n_bytes_read)
{
    struct iovec local;
    struct iovec remote;
    uint8_t *buffer;
    ssize_t n;

    if (len == 0 || address == NULL)
        return NULL;

    /* gum uses g_malloc; keep the same "caller frees" contract. */
    buffer = malloc(len);
    if (buffer == NULL)
        return NULL;

    local.iov_base = buffer;
    local.iov_len = len;
    remote.iov_base = (void *)(uintptr_t)address;
    remote.iov_len = len;

    do {
        n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    } while (n < 0 && errno == EINTR);

    if (n <= 0) {
        free(buffer);
        return NULL;
    }

    if (n != (ssize_t)len) {
        /* Partial read: shrink like gum's g_realloc path. */
        uint8_t *shrunk = realloc(buffer, (size_t)n);
        if (shrunk == NULL) {
            free(buffer);
            return NULL;
        }
        buffer = shrunk;
    }

    if (n_bytes_read != NULL)
        *n_bytes_read = (size_t)n;
    return buffer;
}

int green_gum_memory_write(void *address, const uint8_t *bytes, size_t len)
{
    unsigned long addr = (unsigned long)(uintptr_t)address;

    if (address == NULL || bytes == NULL || len == 0)
        return -1;

    if (len > GREEN_SHADOW_MAX_PATCH_LEN)
        return -1;
    if ((addr & (GREEN_GUM_PAGE_SIZE - 1)) + len > GREEN_GUM_PAGE_SIZE)
        return -1;

    return green_gum_shadow_prctl(PR_GREEN_SHADOW_PATCH, 0, addr,
                                  (unsigned long)(uintptr_t)bytes, len) == 0
               ? 0
               : -1;
}

int green_gum_memory_patch_code(void *address, size_t size,
                                green_gum_patch_apply_fn apply,
                                void *apply_data)
{
    unsigned long addr = (unsigned long)(uintptr_t)address;
    unsigned long offset = addr & (GREEN_GUM_PAGE_SIZE - 1);
    uint8_t buffer[GREEN_GUM_PAGE_SIZE];
    size_t chunk;

    if (address == NULL || apply == NULL || size == 0)
        return -1;
    if (size > GREEN_SHADOW_MAX_PATCH_LEN)
        return -1;
    if (offset + size > GREEN_GUM_PAGE_SIZE)
        return -1; /* gum splits by page; callers here patch within one page */

    /*
     * gum: the apply callback writes into a writable alias of the target
     * page and gum memcpy's the whole page back under mprotect.  green_hook:
     * the apply callback writes into this snapshot; the kernel copies the
     * original page into the shadow page first and then overlays exactly
     * these bytes, so unpatched neighbours keep their original content.
     */
    chunk = size;
    apply(buffer, apply_data);

    return green_gum_shadow_prctl(PR_GREEN_SHADOW_PATCH, 0, addr,
                                  (unsigned long)(uintptr_t)buffer,
                                  chunk) == 0
               ? 0
               : -1;
}

int green_gum_mprotect(void *address, size_t size, int prot)
{
    unsigned long addr = (unsigned long)(uintptr_t)address;
    unsigned long page = GREEN_GUM_PAGE_SIZE;
    unsigned long start = addr & ~(page - 1);
    unsigned long end = (addr + size - 1 + page) & ~(page - 1);

    return mprotect((void *)start, end - start, prot);
}

void green_gum_clear_cache(const void *address, size_t size)
{
    (void)address;
    (void)size;
    /*
     * The kernel performs green_shadow_sync_code() (dc cvau + ic ialluis +
     * TLB) when installing a shadow patch, so the icache is already coherent
     * by the time userspace observes a successful prctl.  Nothing to do.
     */
}

int green_gum_release_page(const void *address)
{
    unsigned long addr = (unsigned long)(uintptr_t)address;

    if (address == NULL)
        return -1;

    return green_gum_shadow_prctl(PR_GREEN_SHADOW_RELEASE, 0,
                                  addr & ~(GREEN_GUM_PAGE_SIZE - 1), 0,
                                  0) == 0
               ? 0
               : -1;
}

/* ===== redirect writers (gumarm64writer encodings) ===== */

static void green_writer_put(uint32_t *code, unsigned int index, uint32_t insn)
{
    code[index] = insn;
}

void green_hook_write_nop(uint32_t *code)
{
    green_writer_put(code, 0, 0xd503201fU);
}

int green_hook_write_branch_b(uint32_t *code, uint64_t pc, uint64_t target)
{
    int64_t distance = (int64_t)target - (int64_t)pc;

    if (distance % 4 != 0)
        return -1;
    if (distance < -(1LL << 27) || distance >= (1LL << 27))
        return -1;

    green_writer_put(code, 0,
                     0x14000000U | (((uint64_t)(distance / 4)) & 0x03ffffffU));
    return 0;
}

void green_hook_write_branch_ldr(uint32_t *code, uint64_t target)
{
    /*
     * gum's full redirect (guminterceptor-arm64.c,
     * GUM_INTERCEPTOR_FULL_REDIRECT_SIZE == 16):
     *
     *   ldr x16, #8      ; 0x58000000 | (imm19 << 5) | rt, imm19 = 8/4 = 2
     *   br  x16          ; 0xd61f0000 | (rt << 5), no ptrauth extra
     *   .quad target     ; literal pool on the same shadow page
     */
    green_writer_put(code, 0, 0x58000000U | (2U << 5) | 16U);
    green_writer_put(code, 1, 0xd61f0000U | (16U << 5));
    code[2] = (uint32_t)(target & 0xffffffffU);
    code[3] = (uint32_t)(target >> 32);
}
