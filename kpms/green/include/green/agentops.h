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

/* BROKER_ATTACH handshake on an already connected socket. */
int green_agentops_broker_attach(pid_t pid, int broker_fd);

int green_agentops_send_request(int fd, uint16_t tool, uint16_t command,
                                uint64_t arg0, uint64_t arg1, uint64_t arg2);
int green_agentops_read_response(int fd, struct green_agent_response *out);

/* Read and service one broker frame (PATCH/RELEASE/COUNT/LOG).  LOG frames
 * are forwarded to logcb instead of being answered.  Returns 0 when a frame
 * was handled, 1 on clean EOF, -1 on error. */
typedef void (*green_agentops_log_cb)(int32_t pid, const char *text,
                                      uint32_t len, void *ud);
int green_agentops_broker_serve_one(pid_t pid, int broker_fd,
                                    green_agentops_log_cb logcb, void *ud);

/* ptrace + remote dlopen of the payload. */
int green_agentops_inject(pid_t pid, const char *so_path);

int green_agentops_read_cmdline(pid_t pid, char *out, size_t out_size);
pid_t green_agentops_find_package(const char *package);
/* Where `file` must live for the target to read it (app cache or next to
 * the target binary). */
void green_agentops_target_path(const char *cmdline, const char *file,
                                char *out, size_t out_size);
/* Copy src to dest, 0644/0755, chowned to the target uid. */
int green_agentops_copy_file(const char *src, const char *dest, pid_t pid,
                             int executable);

/* Inject the payload unless the agent socket already answers. */
int green_agentops_ensure_injected(pid_t pid, char *err, size_t errlen);

/* Deploy the hook script (-l file or -c inline) to the target-readable
 * path; the destination is copied out to dest. */
int green_agentops_deploy_script(pid_t pid, const char *script_file,
                                 const char *inline_code, char *dest,
                                 size_t dest_size, char *err, size_t errlen);

/* One-shot flow used by the on-device `green hook attach` command: ensure
 * injection, deploy the script and evaluate it (serving the broker channel
 * while the request runs). */
int green_agentops_attach_and_load(pid_t pid, const char *script_file,
                                   const char *inline_code);

#endif /* GREEN_AGENTOPS_H */
