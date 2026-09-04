/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GREEN_CLI_H
#define GREEN_CLI_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int green_cli_parse_ulong(const char *s, unsigned long *out);
int green_cli_parse_pid(const char *s, pid_t *out);
int green_cli_hex_to_bytes(const char *hex, unsigned char **out, size_t *out_len);
void green_cli_free(void *p);
long green_cli_prctl(unsigned long option, unsigned long a2, unsigned long a3,
                     unsigned long a4, unsigned long a5);
ssize_t green_cli_process_vm_read(pid_t pid, void *local, size_t length,
                                  unsigned long remote);
/* The linker64 map is used only to locate the linker image; library enumeration
 * is performed from its in-process solist chain. */
unsigned long green_cli_show_exec_solist(pid_t pid, const char *lib_name);
unsigned long green_cli_find_solist(pid_t pid, const char *needle);
pid_t green_cli_effective_pid(pid_t pid);

typedef int (*green_cli_solist_cb)(const char *name, unsigned long base,
                                   unsigned long size, void *ud);
int green_cli_list_solist(pid_t pid, green_cli_solist_cb cb, void *ud);

#endif /* GREEN_CLI_H */
