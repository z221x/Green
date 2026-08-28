/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/symbol.h>
#include <linux/errno.h>
#include <linux/printk.h>

void *(*green_k_find_vma)(void *mm, unsigned long addr);
void *(*green_k_get_task_mm)(void *task);
void (*green_k_mmput)(void *mm);
unsigned long (*green_k_get_free_pages)(unsigned int gfp_mask,
                                        unsigned int order);
void (*green_k_free_pages)(unsigned long addr, unsigned int order);
struct task_struct *(*green_k_find_task_by_vpid)(pid_t pid);
void (*green_k_rcu_read_lock)(void);
void (*green_k_rcu_read_unlock)(void);

void *green_sym_do_page_fault;
void *green_sym_follow_page_pte;
void *green_sym_exit_mmap;

static int green_symbol_equal(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

struct green_symbol_lookup_context {
    const char *name;
    unsigned long address;
};

static int green_symbol_lookup_callback(void *data, const char *name,
                                         struct module *mod,
                                         unsigned long address)
{
    struct green_symbol_lookup_context *context = data;

    (void)mod;
    if (context && green_symbol_equal(name, context->name)) {
        context->address = address;
        return 1;
    }
    return 0;
}

unsigned long green_lookup_symbol(const char *name)
{
    struct green_symbol_lookup_context context;

    if (!name || !name[0])
        return 0;
    context.name = name;
    context.address = 0;

    if (kallsyms_on_each_symbol)
        kallsyms_on_each_symbol(green_symbol_lookup_callback, &context);
    if (!context.address && kallsyms_lookup_name)
        context.address = kallsyms_lookup_name(name);
    return context.address;
}

#define GREEN_RESOLVE_REQUIRED(symbol, target)                                  \
    do {                                                                        \
        target = (typeof(target))green_lookup_symbol(symbol);                   \
        if (!target) {                                                          \
            pr_err("green: missing kernel symbol %s\n", symbol);              \
            return -ESRCH;                                                      \
        }                                                                       \
    } while (0)

int green_resolve_kernel_symbols(void)
{
    GREEN_RESOLVE_REQUIRED("find_vma", green_k_find_vma);
    GREEN_RESOLVE_REQUIRED("get_task_mm", green_k_get_task_mm);
    GREEN_RESOLVE_REQUIRED("mmput", green_k_mmput);
    GREEN_RESOLVE_REQUIRED("__get_free_pages", green_k_get_free_pages);
    GREEN_RESOLVE_REQUIRED("free_pages", green_k_free_pages);
    GREEN_RESOLVE_REQUIRED("find_task_by_vpid", green_k_find_task_by_vpid);

    green_k_rcu_read_lock = (typeof(green_k_rcu_read_lock))
        green_lookup_symbol("__rcu_read_lock");
    green_k_rcu_read_unlock = (typeof(green_k_rcu_read_unlock))
        green_lookup_symbol("__rcu_read_unlock");

    green_sym_do_page_fault = (void *)green_lookup_symbol("do_page_fault");
    green_sym_follow_page_pte = (void *)green_lookup_symbol("follow_page_pte");
    green_sym_exit_mmap = (void *)green_lookup_symbol("exit_mmap");

    if (!green_sym_do_page_fault || !green_sym_exit_mmap) {
        pr_err("green: required hook symbols unavailable fault=%px exit=%px\n",
               green_sym_do_page_fault, green_sym_exit_mmap);
        return -ESRCH;
    }

    pr_info("green: kernel symbols ready fault=%px gup=%px exit=%px\n",
            green_sym_do_page_fault, green_sym_follow_page_pte,
            green_sym_exit_mmap);
    return 0;
}
