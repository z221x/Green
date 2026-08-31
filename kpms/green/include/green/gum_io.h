/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GREEN_GUM_IO_H_
#define _GREEN_GUM_IO_H_

#include <stddef.h>
#include <stdint.h>

/*
 * green_hook: gum-compatible memory I/O backed by the green shadow pager.
 *
 * The API mirrors the subset of frida-gum's gummemory.h that participates in
 * code patching / reading on Linux+ARM64.  Semantics:
 *
 *   patch_code  - writes go to the shadow page; execution observes the patch
 *                 while reads of the same bytes observe the original page.
 *   read        - routed through process_vm_readv (GUP), which the shadow
 *                 kernel module already answers with the original PFN.
 *   release     - restores the original PTE (gum: memcpy of the saved
 *                 prologue back into the target).
 *
 * See hook/IO_MAP.md for the full gum function/call-site mapping.
 */

#define GREEN_GUM_PAGE_SIZE 4096UL

/* gum: GumMemoryPatchApplyFunc (gummemory.h) */
typedef void (*green_gum_patch_apply_fn)(void *mem, void *user_data);

/* gum: gum_memory_read() — returns a malloc'd buffer or NULL. */
uint8_t *green_gum_memory_read(const void *address, size_t len,
                               size_t *n_bytes_read);

/* gum: gum_memory_write() — code pages go through the shadow patch ABI. */
int green_gum_memory_write(void *address, const uint8_t *bytes, size_t len);

/*
 * gum: gum_memory_patch_code(address, size, apply, apply_data)
 *
 * The apply callback receives a plain writable buffer standing in for
 * `address`; whatever it stores there is committed to the shadow page on
 * return.  size must not cross a page boundary (same constraint as the
 * prctl ABI); split across pages like gum does if needed.
 */
int green_gum_memory_patch_code(void *address, size_t size,
                                green_gum_patch_apply_fn apply,
                                void *apply_data);

/* gum: gum_mprotect — native passthrough, for gum's own allocations. */
int green_gum_mprotect(void *address, size_t size, int prot);

/* gum: gum_clear_cache — no-op; the kernel syncs I-cache/TLB at patch time. */
void green_gum_clear_cache(const void *address, size_t size);

/*
 * gum: deactivate_trampoline equivalent — restores the original mapping of
 * the page containing address and drops its shadow state.
 */
int green_gum_release_page(const void *address);

/* Redirect writers (encodings ported from gum/arch-arm64/gumarm64writer.c). */

/* B imm26 to target; returns 0 on success, -1 when out of +/-128MB range. */
int green_hook_write_branch_b(uint32_t *code, uint64_t pc, uint64_t target);

/* LDR x16,#8; BR x16; .quad target — gum's full redirect (16 bytes). */
void green_hook_write_branch_ldr(uint32_t *code, uint64_t target);

/* NOP (d503201f). */
void green_hook_write_nop(uint32_t *code);

#endif /* _GREEN_GUM_IO_H_ */
