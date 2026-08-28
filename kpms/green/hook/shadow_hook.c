/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/shadow_internal.h>

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

struct list_head green_shadow_pages = LIST_HEAD_INIT(green_shadow_pages);
atomic_t green_shadow_pages_busy = ATOMIC_INIT(0);
atomic_t green_shadow_hooks_busy = ATOMIC_INIT(0);
int green_shadow_online;
int green_shadow_va_bits;
int green_shadow_levels;
int green_shadow_root_shift;
s64 green_shadow_linear_offset;
int16_t green_shadow_vma_mm_offset = -1;

static int green_shadow_hooked_prctl;
static int green_shadow_hooked_fault;
static int green_shadow_hooked_gup;
static int green_shadow_hooked_exit;

int green_shadow_detect_vma_mm(void *mm, void *vma)
{
    int off;

    if (!mm || !vma)
        return -EINVAL;

    if (green_shadow_vma_mm_offset >= 0 && green_vma_mm(vma) == mm)
        return 0;

    for (off = 0; off <= 0x100; off += (int)sizeof(void *)) {
        if (*(void **)((char *)vma + off) == mm) {
            green_shadow_vma_mm_offset = off;
            pr_info("green_shadow: detected vm_area_struct.vm_mm offset=0x%x\n", off);
            return 0;
        }
    }

    pr_warn("green_shadow: unable to detect vm_area_struct.vm_mm offset\n");
    return -ENOENT;
}

struct green_shadow_page *green_shadow_get_page(void *mm, unsigned long addr)
{
    struct list_head *pos;
    struct green_shadow_page *page;
    unsigned long va = green_align_down(addr);

    green_lock(&green_shadow_pages_busy);
    list_for_each(pos, &green_shadow_pages) {
        page = container_of(pos, struct green_shadow_page, node);
        if (!page->dead && page->mm == mm && page->va == va) {
            page->refs++;
            green_unlock(&green_shadow_pages_busy);
            return page;
        }
    }
    green_unlock(&green_shadow_pages_busy);
    return 0;
}

void green_shadow_put_page(struct green_shadow_page *page)
{
    int free_it = 0;
    unsigned long shadow = 0;

    if (!page)
        return;

    green_lock(&green_shadow_pages_busy);
    page->refs--;
    if (page->refs == 0) {
        free_it = 1;
        shadow = (unsigned long)page->shadow_kva;
        page->shadow_kva = 0;
    }
    green_unlock(&green_shadow_pages_busy);

    if (free_it) {
        if (shadow)
            green_k_free_pages(shadow, 0);
        green_k_free_pages((unsigned long)page, 0);
    }
}

static struct green_shadow_page *green_shadow_new_page(void *mm,
                                                       unsigned long addr)
{
    struct green_shadow_page *page;
    unsigned long meta;
    unsigned long shadow;
    unsigned long src_kva;
    unsigned long va = green_align_down(addr);
    void *vma;
    u64 *ptep;
    u64 pte;

    vma = green_k_find_vma(mm, va);
    if (!vma || green_vma_start(vma) > va || green_vma_end(vma) <= va)
        return 0;

    if (green_shadow_detect_vma_mm(mm, vma) < 0)
        return 0;

    ptep = green_shadow_get_pte(mm, va);
    if (!ptep || !(*ptep & PTE_VALID))
        return 0;

    pte = *ptep;
    if (!(pte & PTE_USER) || !(pte & PTE_RDONLY) || (pte & PTE_UXN)) {
        pr_warn("green_shadow: target is not a user read-only executable page va=%lx pte=%llx\n",
                va, pte);
        return 0;
    }
#ifdef PTE_CONT
    if (pte & PTE_CONT) {
        pr_warn("green_shadow: contiguous PTE is not supported va=%lx\n", va);
        return 0;
    }
#endif

    meta = green_k_get_free_pages(GREEN_GFP_KERNEL, 0);
    if (!meta)
        return 0;
    memset((void *)meta, 0, GREEN_PAGE_SIZE);

    shadow = green_k_get_free_pages(GREEN_GFP_KERNEL, 0);
    if (!shadow) {
        green_k_free_pages(meta, 0);
        return 0;
    }

    page = (struct green_shadow_page *)meta;
    page->mm = mm;
    page->va = va;
    page->original_pte = pte;
    page->original_pfn = green_pte_pfn(pte);
    page->shadow_kva = (void *)shadow;
    page->shadow_pfn = green_kva_to_phys(shadow) >> GREEN_PAGE_SHIFT;
    page->state = 0;
    page->refs = 2; /* list + caller */
    page->dead = false;
    atomic_set(&page->pte_busy, 0);
    INIT_LIST_HEAD(&page->node);

    src_kva = green_phys_to_kva(page->original_pfn << GREEN_PAGE_SHIFT);
    if (!green_is_kva(src_kva)) {
        green_k_free_pages(shadow, 0);
        green_k_free_pages(meta, 0);
        return 0;
    }
    memcpy(page->shadow_kva, (void *)src_kva, GREEN_PAGE_SIZE);

    {
        struct green_shadow_page *existing = 0;
        struct list_head *pos;
        bool blocked = false;

        /* Allocation happens outside the lock; collapse concurrent creators here. */
        green_lock(&green_shadow_pages_busy);
        list_for_each(pos, &green_shadow_pages) {
            struct green_shadow_page *cur = container_of(pos, struct green_shadow_page, node);
            if (cur->mm != mm || cur->va != va)
                continue;
            if (cur->dead) {
                /* A release is restoring this VA; do not snapshot a transient shadow PTE. */
                blocked = true;
                break;
            }
            cur->refs++;
            existing = cur;
            break;
        }
        if (!existing && !blocked)
            list_add_tail(&page->node, &green_shadow_pages);
        green_unlock(&green_shadow_pages_busy);

        if (existing || blocked) {
            green_k_free_pages((unsigned long)page->shadow_kva, 0);
            green_k_free_pages((unsigned long)page, 0);
            return existing;
        }
    }

    pr_info("green_shadow: created shadow page mm=%px va=%lx orig_pfn=%lx shadow_pfn=%lx\n",
            mm, va, page->original_pfn, page->shadow_pfn);
    return page;
}

int green_shadow_release_page(struct green_shadow_page *page, bool restore)
{
    int linked = 0;

    if (!page)
        return -EINVAL;

    green_lock(&green_shadow_pages_busy);
    if (!page->dead) {
        page->dead = true;
        linked = 1;
    }
    green_unlock(&green_shadow_pages_busy);

    if (restore)
        green_shadow_restore_original(page);

    if (linked) {
        green_lock(&green_shadow_pages_busy);
        list_del_init(&page->node);
        page->refs--; /* drop list reference */
        green_unlock(&green_shadow_pages_busy);
    }

    green_shadow_put_page(page); /* drop caller reference */
    return 0;
}

int green_shadow_release_mm(void *mm, bool restore)
{
    int count = 0;

    for (;;) {
        struct list_head *pos;
        struct green_shadow_page *page = 0;

        green_lock(&green_shadow_pages_busy);
        list_for_each(pos, &green_shadow_pages) {
            struct green_shadow_page *cur = container_of(pos, struct green_shadow_page, node);
            if (!cur->dead && cur->mm == mm) {
                cur->refs++;
                page = cur;
                break;
            }
        }
        green_unlock(&green_shadow_pages_busy);

        if (!page)
            break;
        green_shadow_release_page(page, restore);
        count++;
    }

    return count;
}

int green_shadow_release_all(bool restore)
{
    int count = 0;

    for (;;) {
        struct list_head *pos;
        struct green_shadow_page *page = 0;

        green_lock(&green_shadow_pages_busy);
        list_for_each(pos, &green_shadow_pages) {
            struct green_shadow_page *cur = container_of(pos, struct green_shadow_page, node);
            if (!cur->dead) {
                cur->refs++;
                page = cur;
                break;
            }
        }
        green_unlock(&green_shadow_pages_busy);

        if (!page)
            break;
        green_shadow_release_page(page, restore);
        count++;
    }

    return count;
}

int green_shadow_count_mm(void *mm)
{
    struct list_head *pos;
    int count = 0;

    green_lock(&green_shadow_pages_busy);
    list_for_each(pos, &green_shadow_pages) {
        struct green_shadow_page *page = container_of(pos, struct green_shadow_page, node);
        if (!page->dead && (!mm || page->mm == mm))
            count++;
    }
    green_unlock(&green_shadow_pages_busy);
    return count;
}

void *green_shadow_mm_from_pid(pid_t pid)
{
    void *mm;

    if (pid == 0)
        return green_k_get_task_mm(current);

    if (green_k_rcu_read_lock)
        green_k_rcu_read_lock();
    {
        struct task_struct *task = green_k_find_task_by_vpid(pid);
        mm = task ? green_k_get_task_mm(task) : 0;
    }
    if (green_k_rcu_read_unlock)
        green_k_rcu_read_unlock();

    return mm;
}

int green_shadow_copy_from_user(void *dst, const void __user *src,
                                unsigned long len)
{
    void *mm;
    unsigned long done = 0;
    unsigned long uaddr = (unsigned long)src;

    mm = green_k_get_task_mm(current);
    if (!mm)
        return -ESRCH;

    while (done < len) {
        unsigned long cur = uaddr + done;
        unsigned long off = green_page_off(cur);
        unsigned long chunk = GREEN_PAGE_SIZE - off;
        u64 *ptep;
        unsigned long kva;

        if (chunk > len - done)
            chunk = len - done;

        ptep = green_shadow_get_pte(mm, cur);
        if (!ptep || !(*ptep & PTE_VALID)) {
            green_k_mmput(mm);
            return -EFAULT;
        }

        kva = green_phys_to_kva(green_pte_pfn(*ptep) << GREEN_PAGE_SHIFT);
        if (!green_is_kva(kva)) {
            green_k_mmput(mm);
            return -EFAULT;
        }

        memcpy((char *)dst + done, (void *)(kva + off), chunk);
        done += chunk;
    }

    green_k_mmput(mm);
    return 0;
}

long green_shadow_patch_mm(void *mm, unsigned long addr, const void *buf,
                           unsigned long len, bool from_user)
{
    struct green_shadow_page *page;
    unsigned long off = green_page_off(addr);
    bool created = false;
    int ret;

    if (!green_shadow_online)
        return -EAGAIN;
    if (!mm || !buf || len == 0 || len > GREEN_SHADOW_MAX_PATCH_LEN)
        return -EINVAL;
    if (off + len > GREEN_PAGE_SIZE)
        return -EINVAL;

    page = green_shadow_get_page(mm, addr);
    if (!page) {
        page = green_shadow_new_page(mm, addr);
        created = true;
    }
    if (!page)
        return -EFAULT;

    green_shadow_page_lock(page);
    if (from_user)
        ret = green_shadow_copy_from_user((char *)page->shadow_kva + off,
                                          (const void __user *)buf, len);
    else {
        memcpy((char *)page->shadow_kva + off, buf, len);
        ret = 0;
    }
    green_shadow_page_unlock(page);

    if (ret == 0) {
        ret = green_shadow_map_exec(page);
        if (ret) {
            /* A stale mapping must not leave a modified shadow page tracked. */
            green_shadow_release_page(page, true);
            return ret;
        }
    }

    if (ret && created)
        green_shadow_release_page(page, true);
    else
        green_shadow_put_page(page);

    return ret;
}

long green_shadow_patch_task(pid_t pid, unsigned long addr,
                             const void __user *buf, unsigned long len)
{
    void *mm = green_shadow_mm_from_pid(pid);
    long ret;

    if (!mm)
        return -ESRCH;
    ret = green_shadow_patch_mm(mm, addr, buf, len, true);
    green_k_mmput(mm);
    return ret;
}

long green_shadow_patch_kernel(pid_t pid, unsigned long addr, const void *buf,
                               unsigned long len)
{
    void *mm = green_shadow_mm_from_pid(pid);
    long ret;

    if (!mm)
        return -ESRCH;
    ret = green_shadow_patch_mm(mm, addr, buf, len, false);
    green_k_mmput(mm);
    return ret;
}

long green_shadow_release_task(pid_t pid, unsigned long addr)
{
    void *mm = green_shadow_mm_from_pid(pid);
    struct green_shadow_page *page;
    long ret;

    if (!mm)
        return -ESRCH;

    if (addr == 0) {
        ret = green_shadow_release_mm(mm, true);
        green_k_mmput(mm);
        return ret;
    }

    page = green_shadow_get_page(mm, addr);
    if (!page) {
        green_k_mmput(mm);
        return -ENOENT;
    }

    ret = green_shadow_release_page(page, true);
    green_k_mmput(mm);
    return ret ? ret : 1;
}

long green_shadow_count_task(pid_t pid)
{
    void *mm = green_shadow_mm_from_pid(pid);
    long ret;

    if (!mm)
        return -ESRCH;
    ret = green_shadow_count_mm(mm);
    green_k_mmput(mm);
    return ret;
}

void green_shadow_prctl_before(hook_fargs5_t *args, void *udata)
{
    unsigned long option = syscall_argn(args, 0);
    pid_t pid = (pid_t)syscall_argn(args, 1);
    unsigned long addr = syscall_argn(args, 2);
    unsigned long arg4 = syscall_argn(args, 3);
    unsigned long arg5 = syscall_argn(args, 4);
    long ret = -EINVAL;

    (void)udata;

    if (option < PR_GREEN_SHADOW_PATCH || option > PR_GREEN_SHADOW_COUNT)
        return;

    atomic_inc(&green_shadow_hooks_busy);

    if (current_uid() != 0) {
        ret = -EPERM;
        goto out;
    }

    switch (option) {
    case PR_GREEN_SHADOW_PATCH:
        ret = green_shadow_patch_task(pid, addr, (const void __user *)arg4, arg5);
        break;
    case PR_GREEN_SHADOW_RELEASE:
        ret = green_shadow_release_task(pid, addr);
        break;
    case PR_GREEN_SHADOW_COUNT:
        ret = green_shadow_count_task(pid);
        break;
    default:
        break;
    }

out:
    args->ret = ret;
    args->skip_origin = 1;
    atomic_dec(&green_shadow_hooks_busy);
}

static long green_shadow_control(const char *args, char __user *out_msg, int outlen)
{
    char msg[96];
    int n;
    int count = green_shadow_count_mm(0);

    (void)args;
    n = snprintf(msg, sizeof(msg), "shadow: online=%d pages=%d gup=%d",
                 green_shadow_online, count, green_shadow_hooked_gup);
    if (n < 0)
        return n;
    if (!out_msg || outlen <= 0)
        return 0;
    if (n + 1 > outlen)
        n = outlen - 1;
    msg[n] = '\0';
    return compat_copy_to_user(out_msg, msg, n + 1);
}

static long green_shadow_init(const char *args, const char *event,
                              void __user *reserved)
{
    long ret;

    (void)args;
    (void)event;
    (void)reserved;

    ret = green_resolve_kernel_symbols();
    if (ret)
        return ret;

    ret = green_shadow_detect_paging();
    if (ret)
        return ret;

    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("green_shadow: mm_struct_offset.pgd_offset unavailable\n");
        return -EFAULT;
    }

    ret = hook_syscalln(__NR_prctl, 5, green_shadow_prctl_before, 0, 0);
    if (ret != HOOK_NO_ERR) {
        pr_err("green_shadow: failed to hook prctl: %ld\n", ret);
        return -EFAULT;
    }
    green_shadow_hooked_prctl = 1;

    ret = hook_wrap3(green_sym_do_page_fault, green_shadow_fault_before, 0, 0);
    if (ret != HOOK_NO_ERR) {
        pr_err("green_shadow: failed to hook do_page_fault: %ld\n", ret);
        unhook_syscalln(__NR_prctl, green_shadow_prctl_before, 0);
        green_shadow_hooked_prctl = 0;
        return -EFAULT;
    }
    green_shadow_hooked_fault = 1;

    ret = hook_wrap1(green_sym_exit_mmap, green_shadow_exit_mmap_before, 0, 0);
    if (ret != HOOK_NO_ERR) {
        hook_unwrap(green_sym_do_page_fault, green_shadow_fault_before, 0);
        unhook_syscalln(__NR_prctl, green_shadow_prctl_before, 0);
        green_shadow_hooked_fault = 0;
        green_shadow_hooked_prctl = 0;
        return -EFAULT;
    }
    green_shadow_hooked_exit = 1;

    if (green_sym_follow_page_pte) {
        ret = hook_wrap5(green_sym_follow_page_pte, green_shadow_gup_before,
                         green_shadow_gup_after, 0);
        if (ret == HOOK_NO_ERR)
            green_shadow_hooked_gup = 1;
        else
            pr_warn("green_shadow: follow_page_pte hook unavailable: %ld\n", ret);
    }

    green_shadow_online = 1;
    pr_info("green_shadow: online patch=%lx release=%lx count=%lx\n",
            PR_GREEN_SHADOW_PATCH, PR_GREEN_SHADOW_RELEASE,
            PR_GREEN_SHADOW_COUNT);
    return 0;
}

static long green_shadow_exit(void __user *reserved)
{
    int loops = 0;
    int count;

    (void)reserved;
    green_shadow_online = 0;

    if (green_shadow_hooked_prctl) {
        unhook_syscalln(__NR_prctl, green_shadow_prctl_before, 0);
        green_shadow_hooked_prctl = 0;
    }
    if (green_shadow_hooked_gup) {
        hook_unwrap(green_sym_follow_page_pte, green_shadow_gup_before,
                    green_shadow_gup_after);
        green_shadow_hooked_gup = 0;
    }
    if (green_shadow_hooked_fault) {
        hook_unwrap(green_sym_do_page_fault, green_shadow_fault_before, 0);
        green_shadow_hooked_fault = 0;
    }
    if (green_shadow_hooked_exit) {
        hook_unwrap(green_sym_exit_mmap, green_shadow_exit_mmap_before, 0);
        green_shadow_hooked_exit = 0;
    }

    while (atomic_read(&green_shadow_hooks_busy) > 0 && loops++ < 10000000)
        green_cpu_relax();

    count = green_shadow_release_all(true);
    pr_info("green_shadow: offline released=%d\n", count);
    return 0;
}

const struct green_tool green_shadow_tool = {
    .name = "shadow",
    .init = green_shadow_init,
    .control = green_shadow_control,
    .exit = green_shadow_exit,
};
