/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/shadow_internal.h>

#ifndef __NR_prctl
#define __NR_prctl 167
#endif

struct list_head green_shadow_pages = LIST_HEAD_INIT(green_shadow_pages);
struct list_head green_shadow_tokens = LIST_HEAD_INIT(green_shadow_tokens);
atomic_t green_shadow_pages_busy = ATOMIC_INIT(0);
atomic_t green_shadow_pgtable_busy = ATOMIC_INIT(0);
atomic_t green_shadow_hooks_busy = ATOMIC_INIT(0);
int green_shadow_online;
int green_shadow_va_bits;
int green_shadow_levels;
int green_shadow_root_shift;
s64 green_shadow_linear_offset;
int16_t green_shadow_vma_mm_offset = -1;

static bool green_shadow_token_valid_locked(void *mm, unsigned long token)
{
    struct list_head *pos;

    if (!mm || token == 0)
        return false;
    list_for_each(pos, &green_shadow_tokens) {
        struct green_shadow_token_entry *entry =
            container_of(pos, struct green_shadow_token_entry, node);
        if (entry->mm == mm && entry->token == token)
            return true;
    }
    return false;
}

bool green_shadow_token_valid(void *mm, unsigned long token)
{
    bool valid;

    if (!green_lock(&green_shadow_pages_busy))
        return false;
    valid = green_shadow_token_valid_locked(mm, token);
    green_unlock(&green_shadow_pages_busy);
    return valid;
}

static struct green_shadow_token_entry *
green_shadow_find_token_locked(void *mm)
{
    struct list_head *pos;

    list_for_each(pos, &green_shadow_tokens) {
        struct green_shadow_token_entry *entry =
            container_of(pos, struct green_shadow_token_entry, node);
        if (entry->mm == mm)
            return entry;
    }
    return 0;
}

long green_shadow_register_token(pid_t pid, unsigned long token)
{
    struct green_shadow_token_entry *entry;
    void *mm;

    if (!token)
        return -EINVAL;
    mm = green_shadow_mm_from_pid(pid);
    if (!mm)
        return -ESRCH;

    if (!green_lock(&green_shadow_pages_busy)) {
        green_k_mmput(mm);
        return -EBUSY;
    }
    entry = green_shadow_find_token_locked(mm);
    if (!entry) {
        unsigned long mem = green_k_get_free_pages(GREEN_GFP_KERNEL, 0);
        if (!mem) {
            green_unlock(&green_shadow_pages_busy);
            green_k_mmput(mm);
            return -ENOMEM;
        }
        entry = (struct green_shadow_token_entry *)mem;
        memset(entry, 0, GREEN_PAGE_SIZE);
        INIT_LIST_HEAD(&entry->node);
        entry->mm = mm;
        list_add_tail(&entry->node, &green_shadow_tokens);
    }
    entry->token = token;
    green_unlock(&green_shadow_pages_busy);
    green_k_mmput(mm);
    pr_info("green_shadow: token registered pid=%d mm=%px\n", pid, mm);
    return 0;
}

long green_shadow_revoke_token(pid_t pid, unsigned long token)
{
    struct green_shadow_token_entry *entry;
    void *mm;
    unsigned long mem = 0;

    mm = green_shadow_mm_from_pid(pid);
    if (!mm)
        return -ESRCH;
    if (!green_lock(&green_shadow_pages_busy)) {
        green_k_mmput(mm);
        return -EBUSY;
    }
    entry = green_shadow_find_token_locked(mm);
    if (!entry || (token && entry->token != token)) {
        green_unlock(&green_shadow_pages_busy);
        green_k_mmput(mm);
        return -ENOENT;
    }
    list_del_init(&entry->node);
    mem = (unsigned long)entry;
    green_unlock(&green_shadow_pages_busy);
    green_k_free_pages(mem, 0);
    green_k_mmput(mm);
    pr_info("green_shadow: token revoked pid=%d\n", pid);
    return 0;
}

void green_shadow_revoke_mm(void *mm)
{
    struct green_shadow_token_entry *entry;
    unsigned long mem = 0;

    if (!mm || !green_lock(&green_shadow_pages_busy))
        return;
    entry = green_shadow_find_token_locked(mm);
    if (entry) {
        list_del_init(&entry->node);
        mem = (unsigned long)entry;
    }
    green_unlock(&green_shadow_pages_busy);
    if (mem)
        green_k_free_pages(mem, 0);
}

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

    if (!green_lock(&green_shadow_pages_busy))
        return 0;
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

    if (!green_lock(&green_shadow_pages_busy)) {
        pr_err("green_shadow: put_page lock timeout; leaking page %px\n", page);
        return;
    }
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
    if (!vma || green_vma_start(vma) > va || green_vma_end(vma) <= va) {
        pr_err("green_shadow: new_page: no vma for va=%lx\n", va);
        return 0;
    }

    if (green_shadow_detect_vma_mm(mm, vma) < 0)
        return 0;

    ptep = green_shadow_get_pte(mm, va);
    if (!ptep || !(*ptep & PTE_VALID)) {
        pr_err("green_shadow: new_page: get_pte failed va=%lx ptep=%px pte=%llx\n",
               va, ptep, ptep ? *ptep : 0);
        return 0;
    }

    pte = *ptep;
    if (!(pte & PTE_USER)) {
        pr_warn("green_shadow: target is not a user page va=%lx pte=%llx\n",
                va, pte);
        return 0;
    }

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
    page->executable = (pte & PTE_UXN) == 0;
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
        if (!green_lock(&green_shadow_pages_busy)) {
            green_k_free_pages(shadow, 0);
            green_k_free_pages(meta, 0);
            return 0;
        }
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
    bool claimed = false;
    int ret = 0;

    if (!page)
        return -EINVAL;

    if (!green_lock(&green_shadow_pages_busy))
        return -EBUSY;
    if (!page->dead) {
        page->dead = true;
        claimed = true;
    }
    green_unlock(&green_shadow_pages_busy);

    if (restore) {
        ret = green_shadow_restore_original(page);
        if (ret) {
            /* Never free a shadow page when restoration was not confirmed.
             * Re-open a release we claimed so a later fault/release can retry;
             * a concurrent releaser keeps ownership of an already-dead page. */
            if (claimed) {
                if (green_lock(&green_shadow_pages_busy)) {
                    page->dead = false;
                    green_unlock(&green_shadow_pages_busy);
                } else {
                    pr_err("green_shadow: restore failed and lifecycle lock timed out va=%lx\n",
                           page->va);
                }
            }
            pr_warn("green_shadow: keeping shadow page after restore failure va=%lx ret=%d\n",
                    page->va, ret);
            green_shadow_put_page(page); /* drop caller reference only */
            return ret;
        }
    }

    if (!green_lock(&green_shadow_pages_busy)) {
        /* The PTE is already restored (or restore was not requested), so a
         * lock timeout here can at worst leak metadata; do not risk freeing
         * it without removing the list reference. */
        pr_err("green_shadow: release lifecycle lock timeout va=%lx\n", page->va);
        return -EBUSY;
    }
    if (!list_empty(&page->node)) {
        list_del_init(&page->node);
        page->refs--; /* drop list reference */
    }
    green_unlock(&green_shadow_pages_busy);

    green_shadow_put_page(page); /* drop caller reference */
    return 0;
}

int green_shadow_release_mm(void *mm, bool restore)
{
    int count = 0;

    for (;;) {
        struct list_head *pos;
        struct green_shadow_page *page = 0;

        if (!green_lock(&green_shadow_pages_busy))
            break;
        list_for_each(pos, &green_shadow_pages) {
            struct green_shadow_page *cur = container_of(pos, struct green_shadow_page, node);
            if (cur->mm == mm) {
                cur->refs++;
                page = cur;
                break;
            }
        }
        green_unlock(&green_shadow_pages_busy);

        if (!page)
            break;
        if (green_shadow_release_page(page, restore))
            break;
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

        if (!green_lock(&green_shadow_pages_busy))
            break;
        list_for_each(pos, &green_shadow_pages) {
            struct green_shadow_page *cur = container_of(pos, struct green_shadow_page, node);
            cur->refs++;
            page = cur;
            break;
        }
        green_unlock(&green_shadow_pages_busy);

        if (!page)
            break;
        if (green_shadow_release_page(page, restore))
            break;
        count++;
    }

    return count;
}

static int green_shadow_count_pages(void)
{
    struct list_head *pos;
    int count = 0;

    if (!green_lock(&green_shadow_pages_busy))
        return -EBUSY;
    list_for_each(pos, &green_shadow_pages)
        count++;
    green_unlock(&green_shadow_pages_busy);
    return count;
}

int green_shadow_count_mm(void *mm)
{
    struct list_head *pos;
    int count = 0;

    if (!green_lock(&green_shadow_pages_busy))
        return -EBUSY;
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

    if (!green_shadow_page_lock(page)) {
        green_shadow_put_page(page);
        return -EBUSY;
    }
    if (from_user)
        ret = green_shadow_copy_from_user((char *)page->shadow_kva + off,
                                          (const void __user *)buf, len);
    else {
        memcpy((char *)page->shadow_kva + off, buf, len);
        ret = 0;
    }
    green_shadow_page_unlock(page);

    if (ret == 0) {
        ret = page->executable ? green_shadow_map_exec(page)
                               : green_shadow_map_data(page);
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

long green_shadow_request(const struct green_shadow_rpc *rpc,
                          unsigned long token, bool caller_is_root)
{
    unsigned char bytes[GREEN_SHADOW_MAX_PATCH_LEN];
    void *mm;
    long ret;

    if (!rpc || rpc->version != GREEN_SHADOW_ABI_VERSION ||
        rpc->op < GREEN_SHADOW_OP_PATCH ||
        rpc->op > GREEN_SHADOW_OP_COUNT || token == 0 || rpc->pid < 0)
        return -EINVAL;

    /* Non-root agents may only address their own mm (pid must be 0).  The
     * root server is the sole caller allowed to name another pid. */
    if (!caller_is_root && rpc->pid != 0)
        return -EPERM;

    mm = green_shadow_mm_from_pid((pid_t)rpc->pid);
    if (!mm)
        return -ESRCH;
    if (!green_shadow_token_valid(mm, token)) {
        green_k_mmput(mm);
        return -EACCES;
    }

    switch (rpc->op) {
    case GREEN_SHADOW_OP_PATCH:
        if (!rpc->buf || rpc->len == 0 ||
            rpc->len > GREEN_SHADOW_MAX_PATCH_LEN) {
            ret = -EINVAL;
            break;
        }
        /* The source buffer belongs to the caller (root or the injected
         * process), so copy it before operating on a different target mm. */
        ret = green_shadow_copy_from_user(bytes,
                                          (const void __user *)rpc->buf,
                                          rpc->len);
        if (ret == 0)
            ret = green_shadow_patch_mm(mm, rpc->addr, bytes, rpc->len,
                                        false);
        break;
    case GREEN_SHADOW_OP_RELEASE:
        if (rpc->addr == 0) {
            ret = green_shadow_release_mm(mm, true);
        } else {
            struct green_shadow_page *page =
                green_shadow_get_page(mm, rpc->addr);
            if (!page) {
                ret = -ENOENT;
            } else {
                ret = green_shadow_release_page(page, true);
                if (ret == 0)
                    ret = 1;
            }
        }
        break;
    case GREEN_SHADOW_OP_COUNT:
        ret = green_shadow_count_mm(mm);
        break;
    default:
        ret = -EOPNOTSUPP;
        break;
    }

    green_k_mmput(mm);
    return ret;
}

void green_shadow_prctl_before(hook_fargs5_t *args, void *udata)
{
    unsigned long option = syscall_argn(args, 0);
    unsigned long arg2 = syscall_argn(args, 1);
    unsigned long arg3 = syscall_argn(args, 2);
    unsigned long arg4 = syscall_argn(args, 3);
    unsigned long arg5 = syscall_argn(args, 4);
    long ret = -EINVAL;
    bool caller_is_root = current_uid() == 0;

    (void)udata;

    if (option < PR_GREEN_SHADOW_REQUEST ||
        option > PR_GREEN_SHADOW_TOKEN_REVOKE)
        return;

    atomic_inc(&green_shadow_hooks_busy);

    if (option == PR_GREEN_SHADOW_TOKEN_REGISTER) {
        if (caller_is_root)
            ret = green_shadow_register_token((pid_t)arg2, arg3);
    } else if (option == PR_GREEN_SHADOW_TOKEN_REVOKE) {
        if (caller_is_root)
            ret = green_shadow_revoke_token((pid_t)arg2, arg3);
    } else if (option == PR_GREEN_SHADOW_REQUEST) {
        struct green_shadow_rpc rpc;

        memset(&rpc, 0, sizeof(rpc));
        ret = green_shadow_copy_from_user(&rpc,
                                          (const void __user *)arg3,
                                          sizeof(rpc));
        if (ret == 0)
            ret = green_shadow_request(&rpc, arg2, caller_is_root);
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

    ret = hook_wrap3(green_sym_do_page_fault, green_shadow_fault_before,
                     green_shadow_fault_after, 0);
    if (ret != HOOK_NO_ERR) {
        pr_err("green_shadow: failed to hook do_page_fault: %ld\n", ret);
        unhook_syscalln(__NR_prctl, green_shadow_prctl_before, 0);
        green_shadow_hooked_prctl = 0;
        return -EFAULT;
    }
    green_shadow_hooked_fault = 1;

    ret = hook_wrap1(green_sym_exit_mmap, green_shadow_exit_mmap_before,
                     green_shadow_exit_mmap_after, 0);
    if (ret != HOOK_NO_ERR) {
        hook_unwrap(green_sym_do_page_fault, green_shadow_fault_before,
                    green_shadow_fault_after);
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
    pr_info("green_shadow: online request=%lx token_register=%lx token_revoke=%lx\n",
            PR_GREEN_SHADOW_REQUEST, PR_GREEN_SHADOW_TOKEN_REGISTER,
            PR_GREEN_SHADOW_TOKEN_REVOKE);
    return 0;
}

static long green_shadow_exit(void __user *reserved)
{
    unsigned int loops = 0;
    int count;

    (void)reserved;
    green_shadow_online = 0;

    if (green_shadow_hooked_prctl) {
        unhook_syscalln(__NR_prctl, green_shadow_prctl_before, 0);
        green_shadow_hooked_prctl = 0;
    }
    /* KPM unload frees this module immediately after this callback returns.
     * A bounded wait would therefore turn a slow callback into UAF in the
     * hook trampolines or shadow pages.  Wait until all in-flight callbacks
     * drain; emit a heartbeat instead of silently proceeding after timeout. */
    while (atomic_read(&green_shadow_hooks_busy) > 0) {
        if (++loops == 10000000u) {
            pr_warn("green_shadow: waiting for %d in-flight hooks\n",
                    atomic_read(&green_shadow_hooks_busy));
            loops = 0;
        }
        green_cpu_relax();
    }

    /* Restore and unlink every page before removing the fault/GUP hooks.  A
     * failed restore leaves the page on the list and is retried here; this
     * prevents unloading code while a user PTE can still name shadow_kva. */
    count = 0;
    for (;;) {
        int pending = green_shadow_count_pages();

        if (pending == 0)
            break;
        if (pending < 0) {
            green_cpu_relax();
            continue;
        }
        count += green_shadow_release_all(true);
        pending = green_shadow_count_pages();
        if (pending != 0)
            green_cpu_relax();
    }

    if (green_shadow_hooked_gup) {
        hook_unwrap(green_sym_follow_page_pte, green_shadow_gup_before,
                    green_shadow_gup_after);
        green_shadow_hooked_gup = 0;
    }
    if (green_shadow_hooked_fault) {
        hook_unwrap(green_sym_do_page_fault, green_shadow_fault_before,
                    green_shadow_fault_after);
        green_shadow_hooked_fault = 0;
    }
    if (green_shadow_hooked_exit) {
        hook_unwrap(green_sym_exit_mmap, green_shadow_exit_mmap_before,
                    green_shadow_exit_mmap_after);
        green_shadow_hooked_exit = 0;
    }

    /* Drop any token entries whose target mm outlived the normal exit_mmap
     * callback (for example when unloading the KPM while a process is being
     * torn down). */
    for (;;) {
        struct green_shadow_token_entry *entry = 0;
        unsigned long mem = 0;
        struct list_head *pos;

        if (!green_lock(&green_shadow_pages_busy))
            break;
        list_for_each(pos, &green_shadow_tokens) {
            entry = container_of(pos, struct green_shadow_token_entry, node);
            list_del_init(&entry->node);
            mem = (unsigned long)entry;
            break;
        }
        green_unlock(&green_shadow_pages_busy);
        if (!mem)
            break;
        green_k_free_pages(mem, 0);
    }

    pr_info("green_shadow: offline released=%d\n", count);
    return 0;
}

const struct green_tool green_shadow_tool = {
    .name = "shadow",
    .init = green_shadow_init,
    .control = green_shadow_control,
    .exit = green_shadow_exit,
};
