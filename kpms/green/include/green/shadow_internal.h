/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_GREEN_SHADOW_INTERNAL_H_
#define _KPM_GREEN_SHADOW_INTERNAL_H_

#include <compiler.h>
#include <ktypes.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <pgtable.h>
#include <green/hook.h>
#include <green/emu.h>
#include <green/symbol.h>

#define GREEN_PAGE_SHIFT 12UL
#define GREEN_PAGE_SIZE  (1UL << GREEN_PAGE_SHIFT)
#define GREEN_PAGE_MASK  (~(GREEN_PAGE_SIZE - 1))
#define GREEN_PTE_INDEX_MASK 0x1ffUL
#define GREEN_PTE_ADDR_MASK  0x0000fffffffff000UL
#define GREEN_GFP_KERNEL 0xcc0U

#define GREEN_SHADOW_STATE_EXEC 1
#define GREEN_SHADOW_STATE_READ 2

struct green_shadow_page {
    struct list_head node;
    void *mm;
    unsigned long va;
    u64 original_pte;
    unsigned long original_pfn;
    void *shadow_kva;
    unsigned long shadow_pfn;
    int state;
    int refs;
    bool dead;
    atomic_t pte_busy;
};

extern struct list_head green_shadow_pages;
extern atomic_t green_shadow_pages_busy;
extern atomic_t green_shadow_hooks_busy;
extern int green_shadow_online;
extern int green_shadow_va_bits;
extern int green_shadow_levels;
extern int green_shadow_root_shift;
extern s64 green_shadow_linear_offset;
extern int16_t green_shadow_vma_mm_offset;

/* All in-kernel spinlocks are bounded: on timeout the caller fails the
 * operation gracefully instead of wedging an EL1 thread (which cannot be
 * killed or attached).  A leaked page or an unhandled fault is always
 * preferable to a permanently spinning CPU. */
#define GREEN_LOCK_MAX_ITER 100000000u

static inline void green_cpu_relax(void)
{
    asm volatile("yield" ::: "memory");
}

static inline bool green_lock(atomic_t *lock)
{
    unsigned int iter = GREEN_LOCK_MAX_ITER;

    while (atomic_cmpxchg(lock, 0, 1) != 0) {
        if (--iter == 0)
            return false;
        green_cpu_relax();
    }
    return true;
}

static inline void green_unlock(atomic_t *lock)
{
    asm volatile("" ::: "memory");
    atomic_set(lock, 0);
}

static inline bool green_shadow_page_lock(struct green_shadow_page *page)
{
    return green_lock(&page->pte_busy);
}

static inline void green_shadow_page_unlock(struct green_shadow_page *page)
{
    green_unlock(&page->pte_busy);
}

static inline unsigned long green_align_down(unsigned long addr)
{
    if (green_shadow_va_bits > 0 && green_shadow_va_bits < 64)
        addr &= (1UL << green_shadow_va_bits) - 1;
    return addr & GREEN_PAGE_MASK;
}

static inline unsigned long green_page_off(unsigned long addr)
{
    return addr & (GREEN_PAGE_SIZE - 1);
}

static inline bool green_is_kva(unsigned long addr)
{
    return (addr >> 48) == 0xffffUL;
}

static inline unsigned long green_phys_to_kva(unsigned long pa)
{
    return pa + green_shadow_linear_offset;
}

static inline unsigned long green_kva_to_phys(unsigned long va)
{
    return va - green_shadow_linear_offset;
}

static inline unsigned long green_pte_pfn(u64 pte)
{
    return (unsigned long)((pte & GREEN_PTE_ADDR_MASK) >> GREEN_PAGE_SHIFT);
}

static inline u64 green_pte_replace_pfn(u64 pte, unsigned long pfn)
{
    return (pte & ~GREEN_PTE_ADDR_MASK) | ((u64)pfn << GREEN_PAGE_SHIFT);
}

static inline unsigned long green_vma_start(void *vma)
{
    return *(unsigned long *)((char *)vma + 0x00);
}

static inline unsigned long green_vma_end(void *vma)
{
    return *(unsigned long *)((char *)vma + 0x08);
}

static inline void *green_vma_mm(void *vma)
{
    if (green_shadow_vma_mm_offset < 0)
        return 0;
    return *(void **)((char *)vma + green_shadow_vma_mm_offset);
}

static inline void *green_mm_pgd(void *mm)
{
    if (mm_struct_offset.pgd_offset < 0)
        return 0;
    return *(void **)((char *)mm + mm_struct_offset.pgd_offset);
}

int green_shadow_detect_paging(void);
int green_shadow_detect_vma_mm(void *mm, void *vma);

u64 *green_shadow_get_pte(void *mm, unsigned long addr);
void green_shadow_write_pte(u64 *ptep, u64 value);
void green_shadow_flush_tlb(unsigned long addr);
void green_shadow_sync_code(void *kva, unsigned long len);
int green_shadow_map_exec(struct green_shadow_page *page);
int green_shadow_map_read(struct green_shadow_page *page);
int green_shadow_restore_original(struct green_shadow_page *page);

struct green_shadow_page *green_shadow_get_page(void *mm, unsigned long addr);
void green_shadow_put_page(struct green_shadow_page *page);
int green_shadow_release_page(struct green_shadow_page *page, bool restore);
int green_shadow_release_mm(void *mm, bool restore);
int green_shadow_release_all(bool restore);
int green_shadow_count_mm(void *mm);
void *green_shadow_mm_from_pid(pid_t pid);
int green_shadow_copy_from_user(void *dst, const void __user *src, unsigned long len);
long green_shadow_patch_mm(void *mm, unsigned long addr, const void *buf,
                           unsigned long len, bool from_user);

void green_shadow_prctl_before(hook_fargs5_t *args, void *udata);
void green_shadow_fault_before(hook_fargs3_t *args, void *udata);
void green_shadow_gup_before(hook_fargs5_t *args, void *udata);
void green_shadow_gup_after(hook_fargs5_t *args, void *udata);
void green_shadow_exit_mmap_before(hook_fargs1_t *args, void *udata);

#endif /* _KPM_GREEN_SHADOW_INTERNAL_H_ */
