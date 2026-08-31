/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/shadow_internal.h>

static unsigned long green_strip_tag(unsigned long addr)
{
    if (green_shadow_va_bits > 0 && green_shadow_va_bits < 64)
        addr &= (1UL << green_shadow_va_bits) - 1;
    return addr;
}

static unsigned long green_at_el1_pa(unsigned long va)
{
    u64 par;

    asm volatile("at s1e1r, %0" : : "r"(va));
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, par_el1" : "=r"(par));
    if (par & 1)
        return 0;
    return (par & GREEN_PTE_ADDR_MASK) | (va & (GREEN_PAGE_SIZE - 1));
}

int green_shadow_detect_paging(void)
{
    u64 tcr;
    unsigned long test_page;
    unsigned long test_pa;
    int tg0;
    int t0sz;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));

    tg0 = (int)((tcr >> 14) & 3);
    if (tg0 != 0) {
        pr_err("green_shadow: only 4K user granule is supported now (TG0=%d)\n", tg0);
        return -EOPNOTSUPP;
    }

    t0sz = (int)(tcr & 0x3f);
    green_shadow_va_bits = 64 - t0sz;
    green_shadow_levels = (green_shadow_va_bits - (int)GREEN_PAGE_SHIFT + 8) / 9;
    if (green_shadow_levels < 2 || green_shadow_levels > 4) {
        pr_err("green_shadow: unsupported user VA layout bits=%d levels=%d\n",
               green_shadow_va_bits, green_shadow_levels);
        return -EOPNOTSUPP;
    }
    green_shadow_root_shift = (int)GREEN_PAGE_SHIFT + 9 * (green_shadow_levels - 1);

    test_page = green_k_get_free_pages(GREEN_GFP_KERNEL, 0);
    if (!test_page)
        return -ENOMEM;

    test_pa = green_at_el1_pa(test_page);
    if (!test_pa) {
        green_k_free_pages(test_page, 0);
        return -EFAULT;
    }

    green_shadow_linear_offset = (s64)test_page - (s64)test_pa;
    green_k_free_pages(test_page, 0);

    pr_info("green_shadow: VA_BITS=%d levels=%d root_shift=%d linear_off=0x%llx\n",
            green_shadow_va_bits, green_shadow_levels, green_shadow_root_shift,
            green_shadow_linear_offset);
    return 0;
}

u64 *green_shadow_get_pte(void *mm, unsigned long addr)
{
    u64 *table;
    int shift;

    addr = green_strip_tag(addr);
    table = (u64 *)green_mm_pgd(mm);
    if (!table || !green_is_kva((unsigned long)table))
        return 0;

    for (shift = green_shadow_root_shift; shift > (int)GREEN_PAGE_SHIFT; shift -= 9) {
        u64 desc = table[(addr >> shift) & GREEN_PTE_INDEX_MASK];
        unsigned long next_pa;
        unsigned long next_va;

        if (!(desc & PTE_VALID))
            return 0;
        if (!(desc & PTE_TABLE_BIT))
            return 0;

        next_pa = desc & GREEN_PTE_ADDR_MASK;
        next_va = green_phys_to_kva(next_pa);
        if (!green_is_kva(next_va))
            return 0;
        table = (u64 *)next_va;
    }

    return &table[(addr >> GREEN_PAGE_SHIFT) & GREEN_PTE_INDEX_MASK];
}

void green_shadow_write_pte(u64 *ptep, u64 value)
{
    *ptep = value;
    asm volatile("dsb ishst" ::: "memory");
}

void green_shadow_flush_tlb(unsigned long addr)
{
    unsigned long operand = (addr >> GREEN_PAGE_SHIFT) & ((1UL << 44) - 1);

    asm volatile("dsb ishst" ::: "memory");
    asm volatile("tlbi vaale1is, %0" : : "r"(operand) : "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

void green_shadow_sync_code(void *kva, unsigned long len)
{
    unsigned long start = (unsigned long)kva;
    unsigned long end = start + len;
    unsigned long line;
    unsigned long ctr;
    unsigned long step;

    asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
    step = 4UL << ((ctr >> 16) & 0xf);
    for (line = start & ~(step - 1); line < end; line += step)
        asm volatile("dc cvau, %0" : : "r"(line) : "memory");

    asm volatile("dsb ish" ::: "memory");
    asm volatile("ic ialluis" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

static u64 green_shadow_exec_pte(struct green_shadow_page *page)
{
    u64 pte = green_pte_replace_pfn(page->original_pte, page->shadow_pfn);

    /* Execute-only, matching the kernel's PAGE_EXECONLY encoding:
     *   AP[2:1] = 0b10  (PTE_RDONLY set, PTE_USER clear)
     *   UXN     = 0
     * EL0 may fetch from this mapping but any data read faults, which is
     * what drives the read-fault seesaw and the same-page emulator.
     * Privileged access to this mapping is intentionally allowed by the
     * project policy; Green's own shadow reads use the kernel linear alias. */
    pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF | PTE_SPECIAL | PTE_RDONLY;
    pte &= ~(u64)(PTE_USER | PTE_UXN);
#ifdef PTE_DBM
    pte &= ~(u64)PTE_DBM;
#endif
#ifdef PTE_DIRTY
    pte &= ~(u64)PTE_DIRTY;
#endif
    return pte;
}

static u64 green_shadow_read_pte(struct green_shadow_page *page)
{
    u64 pte = green_pte_replace_pfn(page->original_pte, page->original_pfn);

    pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF | PTE_USER | PTE_RDONLY | PTE_UXN;
#ifdef PTE_DBM
    pte &= ~(u64)PTE_DBM;
#endif
#ifdef PTE_DIRTY
    pte &= ~(u64)PTE_DIRTY;
#endif
    return pte;
}

int green_shadow_map_exec(struct green_shadow_page *page)
{
    u64 *ptep;
    u64 pte;

    green_shadow_sync_code(page->shadow_kva, GREEN_PAGE_SIZE);
    green_shadow_page_lock(page);
    green_lock(&green_shadow_pages_busy);
    if (page->dead) {
        green_unlock(&green_shadow_pages_busy);
        green_shadow_page_unlock(page);
        return -ENOENT;
    }
    green_unlock(&green_shadow_pages_busy);
    ptep = green_shadow_get_pte(page->mm, page->va);
    if (!ptep) {
        green_shadow_page_unlock(page);
        return -EFAULT;
    }
    if (green_pte_pfn(*ptep) != page->original_pfn &&
        green_pte_pfn(*ptep) != page->shadow_pfn) {
        green_shadow_page_unlock(page);
        return -ESTALE;
    }
    pte = green_shadow_exec_pte(page);
    green_shadow_write_pte(ptep, pte);
    page->state = GREEN_SHADOW_STATE_EXEC;
    green_shadow_page_unlock(page);
    green_shadow_flush_tlb(page->va);
    return 0;
}

int green_shadow_map_read(struct green_shadow_page *page)
{
    u64 *ptep;
    u64 pte;

    green_shadow_page_lock(page);
    green_lock(&green_shadow_pages_busy);
    if (page->dead) {
        green_unlock(&green_shadow_pages_busy);
        green_shadow_page_unlock(page);
        return -ENOENT;
    }
    green_unlock(&green_shadow_pages_busy);
    ptep = green_shadow_get_pte(page->mm, page->va);
    if (!ptep) {
        green_shadow_page_unlock(page);
        return -EFAULT;
    }
    if (green_pte_pfn(*ptep) != page->shadow_pfn) {
        green_shadow_page_unlock(page);
        return -ESTALE;
    }
    pte = green_shadow_read_pte(page);
    green_shadow_write_pte(ptep, pte);
    page->state = GREEN_SHADOW_STATE_READ;
    green_shadow_page_unlock(page);
    green_shadow_flush_tlb(page->va);
    return 0;
}

int green_shadow_restore_original(struct green_shadow_page *page)
{
    u64 *ptep;

    green_shadow_page_lock(page);
    ptep = green_shadow_get_pte(page->mm, page->va);
    if (ptep) {
        unsigned long cur_pfn = green_pte_pfn(*ptep);
        if (cur_pfn == page->shadow_pfn || cur_pfn == page->original_pfn)
            green_shadow_write_pte(ptep, page->original_pte);
        else
            ptep = 0;
    }
    page->state = 0;
    green_shadow_page_unlock(page);
    green_shadow_flush_tlb(page->va);
    return ptep ? 0 : -EFAULT;
}
