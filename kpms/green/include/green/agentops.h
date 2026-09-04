/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GREEN_AGENTOPS_H
#define GREEN_AGENTOPS_H

/* Shared primitives for driving the in-process agent payload: used by the
 * on-device `green hook` command and by the `green server` daemon. */

#include <green_agent.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define GREEN_AGENT_SO_SOURCE "/data/local/tmp/libgreen_agent.so"
#define GREEN_AGENT_SCRIPT_NAME "green_hook.js"

int green_agentops_read_full(int fd, void *buf, size_t size);
int green_agentops_write_full(int fd, const void *buf, size_t size);

int green_agentops_connect(pid_t pid);
int green_agentops_ping_ok(pid_t pid);

int green_agentops_send_request(int fd, uint16_t tool, uint16_t command,
                                uint64_t arg0, uint64_t arg1, uint64_t arg2);
int green_agentops_read_response(int fd, struct green_agent_response *out);

/* Generate, register and deliver a per-mm token.  The KPM registration is
 * performed by this root-side server; the agent receives the same value over
 * its authenticated control socket and includes it in every shadow prctl. */
int green_agentops_authorize(pid_t pid, unsigned long *token,
                             char *err, size_t errlen);
int green_agentops_revoke(pid_t pid, unsigned long token);

/* ptrace + remote dlopen of the payload. */
int green_agentops_inject(pid_t pid, const char *so_path,
                          unsigned long shadow_token);

int green_agentops_read_cmdline(pid_t pid, char *out, size_t out_size);
pid_t green_agentops_find_package(const char *package);
/* Where `file` must live for the target to read it (app cache, app code_cache
 * for libgreen_agent.so, or next to a non-app target binary). */
void green_agentops_target_path(const char *cmdline, const char *file,
                                char *out, size_t out_size);
/* Copy src to dest, 0644/0755, chowned to the target uid. */
int green_agentops_copy_file(const char *src, const char *dest, pid_t pid,
                             int executable);

/* Inject the payload unless the agent socket already answers. */
int green_agentops_ensure_injected(pid_t pid, unsigned long shadow_token,
                                   char *err, size_t errlen);

/* Deploy the hook script (-l file or -c inline) to the target-readable
 * path; the destination is copied out to dest. */
int green_agentops_deploy_script(pid_t pid, const char *script_file,
                                 const char *inline_code, char *dest,
                                 size_t dest_size, char *err, size_t errlen);

#endif /* GREEN_AGENTOPS_H */
