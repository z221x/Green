/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/shadow_internal.h>

#define GREEN_ESR_EC_SHIFT 26
#define GREEN_ESR_EC(esr) (((esr) >> GREEN_ESR_EC_SHIFT) & 0x3f)
#define GREEN_ESR_EC_IABT_LOW 0x20
#define GREEN_ESR_EC_DABT_LOW 0x24
#define GREEN_ESR_FSC(esr) ((esr) & 0x3f)
#define GREEN_ESR_WNR (1U << 6)
#define GREEN_ESR_S1PTW (1U << 7)
#define GREEN_ESR_CM (1U << 8)
#define GREEN_FOLL_WRITE 0x01

#define GREEN_FAULT_NONE  0
#define GREEN_FAULT_EXEC  1
#define GREEN_FAULT_READ  2
#define GREEN_FAULT_WRITE 3

struct green_shadow_emu_context {
    struct green_shadow_page *page;
};

static int green_shadow_emu_read(void *ctx, u64 addr, void *buf,
                                 unsigned int size)
{
    struct green_shadow_emu_context *memory = ctx;
    struct green_shadow_page *page;
    unsigned long offset;
    unsigned long kva;

    if (!memory || !memory->page || !buf || size == 0)
        return GREEN_EMU_BAD_MEMORY;
    page = memory->page;
    if (green_align_down((unsigned long)addr) != page->va)
        return GREEN_EMU_BAD_MEMORY;
    offset = green_page_off((unsigned long)addr);
    if (offset > GREEN_PAGE_SIZE || size > GREEN_PAGE_SIZE - offset)
        return GREEN_EMU_BAD_MEMORY;

    kva = green_phys_to_kva(page->original_pfn << GREEN_PAGE_SHIFT);
    if (!green_is_kva(kva))
        return GREEN_EMU_BAD_MEMORY;
    memcpy(buf, (void *)(kva + offset), size);
    return 0;
}

static int green_shadow_emulate_same_page(struct green_shadow_page *page,
                                          struct pt_regs *regs,
                                          unsigned long far)
{
    struct green_shadow_emu_context context;
    struct green_emu_mem memory;
    struct green_emu_cpu cpu;
    struct green_emu_result result;
    u32 insn;
    unsigned long offset;
    int i;
    int ret;

    if (!page || !regs || green_align_down(regs->pc) != page->va)
        return GREEN_EMU_UNSUPPORTED;
    offset = green_page_off(regs->pc);
    if ((regs->pc & 3) != 0 || offset > GREEN_PAGE_SIZE - 4)
        return GREEN_EMU_UNSUPPORTED;

    /* Serialize against patching and PTE/lifecycle changes. */
    green_shadow_page_lock(page);
    green_lock(&green_shadow_pages_busy);
    if (page->dead || page->state != GREEN_SHADOW_STATE_EXEC ||
        !page->shadow_kva || !page->original_pfn) {
        green_unlock(&green_shadow_pages_busy);
        green_shadow_page_unlock(page);
        return GREEN_EMU_UNSUPPORTED;
    }
    green_unlock(&green_shadow_pages_busy);

    memcpy(&insn, (char *)page->shadow_kva + offset, sizeof(insn));
    for (i = 0; i < 31; i++)
        cpu.x[i] = regs->regs[i];
    cpu.sp = regs->sp;
    cpu.pc = regs->pc;
    cpu.pstate = regs->pstate;

    context.page = page;
    memory.ctx = &context;
    memory.read = green_shadow_emu_read;
    memory.write = 0; /* A shadow code page is never writable. */
    /* Compare the page offset below instead of relying on tagged FAR equality. */
    memory.fault_addr = 0;

    ret = green_emu_step(&cpu, insn, &memory, &result);
    if (ret == GREEN_EMU_OK &&
        (green_align_down(result.address) != page->va ||
         green_page_off(result.address) != green_page_off(far)))
        ret = GREEN_EMU_BAD_MEMORY;
    if (ret == GREEN_EMU_OK) {
        for (i = 0; i < 31; i++)
            regs->regs[i] = cpu.x[i];
        regs->sp = cpu.sp;
        regs->pc = cpu.pc;
        regs->pstate = cpu.pstate;
    }

    green_shadow_page_unlock(page);
    return ret;
}

static int green_shadow_fault_kind(unsigned int esr)
{
    unsigned int ec;
    unsigned int fsc;

    fsc = GREEN_ESR_FSC(esr);
    if ((fsc & 0x3c) != 0x0c)
        return GREEN_FAULT_NONE;

    ec = GREEN_ESR_EC(esr);
    if (ec == GREEN_ESR_EC_IABT_LOW)
        return GREEN_FAULT_EXEC;

    if (ec != GREEN_ESR_EC_DABT_LOW)
        return GREEN_FAULT_NONE;
    if (esr & GREEN_ESR_S1PTW)
        return GREEN_FAULT_NONE;
    if (esr & GREEN_ESR_CM)
        return GREEN_FAULT_READ;
    return (esr & GREEN_ESR_WNR) ? GREEN_FAULT_WRITE : GREEN_FAULT_READ;
}

static u64 green_shadow_read_pte_for_gup(struct green_shadow_page *page)
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

void green_shadow_fault_before(hook_fargs3_t *args, void *udata)
{
    unsigned long far = (unsigned long)args->arg0;
    unsigned int esr = (unsigned int)args->arg1;
    struct green_shadow_page *page;
    struct pt_regs *regs = (struct pt_regs *)(unsigned long)args->arg2;
    void *mm;
    int kind;
    int ret = -1;
    int same_page;

    (void)udata;
    if (!green_shadow_online)
        return;

    kind = green_shadow_fault_kind(esr);
    if (kind == GREEN_FAULT_NONE)
        return;

    atomic_inc(&green_shadow_hooks_busy);

    mm = green_k_get_task_mm(current);
    if (!mm)
        goto out;

    page = green_shadow_get_page(mm, far);
    if (!page) {
        green_k_mmput(mm);
        goto out;
    }

    same_page = regs && green_align_down(regs->pc) == page->va;
    if (kind == GREEN_FAULT_EXEC && page->state == GREEN_SHADOW_STATE_READ) {
        ret = green_shadow_map_exec(page);
        if (ret == 0) {
            args->ret = 0;
            args->skip_origin = 1;
        }
    } else if (kind == GREEN_FAULT_READ && page->state == GREEN_SHADOW_STATE_EXEC) {
        if (same_page) {
            /* The instruction and data use the same VA/PTE.  Switching the
             * whole page to original would immediately cause an instruction
             * abort and replay this data abort forever. */
            ret = green_shadow_emulate_same_page(page, regs, far);
            if (ret == GREEN_EMU_OK) {
                args->ret = 0;
                args->skip_origin = 1;
            }
        } else {
            ret = green_shadow_map_read(page);
            if (ret == 0) {
                args->ret = 0;
                args->skip_origin = 1;
            }
        }
    } else if (kind == GREEN_FAULT_WRITE) {
        /* Code pages should not be written. Restore and let the real fault path handle COW/permission. */
        green_shadow_release_page(page, true);
        green_k_mmput(mm);
        goto out;
    }

    green_shadow_put_page(page);
    green_k_mmput(mm);

out:
    atomic_dec(&green_shadow_hooks_busy);
}

void green_shadow_gup_before(hook_fargs5_t *args, void *udata)
{
    void *vma = (void *)args->arg0;
    unsigned long addr = (unsigned long)args->arg1;
    unsigned int flags = (unsigned int)args->arg3;
    void *mm;
    struct green_shadow_page *page;
    u64 *ptep;
    u64 saved;

    (void)udata;
    args->arg5 = 0;
    args->arg6 = 0;
    args->arg7 = 0;

    if (!green_shadow_online || !vma || (flags & GREEN_FOLL_WRITE))
        return;

    mm = green_vma_mm(vma);
    if (!mm)
        return;

    atomic_inc(&green_shadow_hooks_busy);

    page = green_shadow_get_page(mm, addr);
    if (!page)
        goto out;

    if (page->state != GREEN_SHADOW_STATE_EXEC) {
        green_shadow_put_page(page);
        goto out;
    }

    green_shadow_page_lock(page);
    ptep = green_shadow_get_pte(mm, page->va);
    if (!ptep) {
        green_shadow_page_unlock(page);
        green_shadow_put_page(page);
        goto out;
    }

    saved = *ptep;
    if (green_pte_pfn(saved) != page->shadow_pfn) {
        green_shadow_page_unlock(page);
        green_shadow_put_page(page);
        goto out;
    }
    green_shadow_write_pte(ptep, green_shadow_read_pte_for_gup(page));

    args->arg5 = (unsigned long)page;
    args->arg6 = saved;
    args->arg7 = (unsigned long)ptep;
    return;

out:
    atomic_dec(&green_shadow_hooks_busy);
}

void green_shadow_gup_after(hook_fargs5_t *args, void *udata)
{
    struct green_shadow_page *page = (struct green_shadow_page *)args->arg5;
    u64 saved = (u64)args->arg6;
    u64 *ptep = (u64 *)args->arg7;

    (void)udata;
    if (!page)
        return;

    if (ptep)
        green_shadow_write_pte(ptep, saved);
    green_shadow_page_unlock(page);
    green_shadow_put_page(page);
    atomic_dec(&green_shadow_hooks_busy);
}

void green_shadow_exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)args->arg0;

    (void)udata;
    if (!mm)
        return;

    atomic_inc(&green_shadow_hooks_busy);
    /* Restore before exit_mmap drops the PTE; do not leave a freed shadow
     * page for the normal unmap path to inspect. */
    green_shadow_release_mm(mm, true);
    atomic_dec(&green_shadow_hooks_busy);
}
