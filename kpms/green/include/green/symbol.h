/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_GREEN_SYMBOL_H_
#define _KPM_GREEN_SYMBOL_H_

#include <ktypes.h>
#include <kallsyms.h>

struct task_struct;

/* Resolved kernel function addresses used by Green. */
extern void *(*green_k_find_vma)(void *mm, unsigned long addr);
extern void *(*green_k_get_task_mm)(void *task);
extern void (*green_k_mmput)(void *mm);
extern unsigned long (*green_k_get_free_pages)(unsigned int gfp_mask,
                                                unsigned int order);
extern void (*green_k_free_pages)(unsigned long addr, unsigned int order);
extern struct task_struct *(*green_k_find_task_by_vpid)(pid_t pid);
extern void (*green_k_rcu_read_lock)(void);
extern void (*green_k_rcu_read_unlock)(void);

/* Resolved hook target addresses. */
extern void *green_sym_do_page_fault;
extern void *green_sym_follow_page_pte;
extern void *green_sym_exit_mmap;

unsigned long green_lookup_symbol(const char *name);
int green_resolve_kernel_symbols(void);

#endif /* _KPM_GREEN_SYMBOL_H_ */
