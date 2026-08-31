/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/cli.h>
#include <green/shadow.h>
#include <green_agent.h>
#include <green/abi.h>

#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/un.h>
#include <unistd.h>

#include <gum/arch-arm64/gumarm64writer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define A64_NOP 0xd503201fU

static void put_u32_le(unsigned char out[4], unsigned int v)
{
    out[0] = (unsigned char)(v & 0xff);
    out[1] = (unsigned char)((v >> 8) & 0xff);
    out[2] = (unsigned char)((v >> 16) & 0xff);
    out[3] = (unsigned char)((v >> 24) & 0xff);
}

int green_shadow_request_patch(pid_t pid, unsigned long addr,
                               const void *bytes, size_t len)
{
    long ret;

    if (!bytes || len == 0 || len > GREEN_SHADOW_MAX_PATCH_LEN) {
        fprintf(stderr, "invalid patch length: %zu\n", len);
        return 1;
    }

    ret = green_cli_prctl(PR_GREEN_SHADOW_PATCH, (unsigned long)pid, addr,
                          (unsigned long)bytes, (unsigned long)len);
    if (ret < 0) {
        fprintf(stderr, "shadow patch failed: %s (%ld)\n", strerror((int)-ret), ret);
        return 1;
    }
    return 0;
}

int green_shadow_request_release(pid_t pid, unsigned long addr)
{
    long ret = green_cli_prctl(PR_GREEN_SHADOW_RELEASE, (unsigned long)pid,
                               addr, 0, 0);

    if (ret < 0) {
        fprintf(stderr, "shadow release failed: %s (%ld)\n", strerror((int)-ret), ret);
        return 1;
    }
    printf("released %ld shadow page(s) for pid %d\n", ret, green_cli_effective_pid(pid));
    return 0;
}

long green_shadow_request_count(pid_t pid)
{
    return green_cli_prctl(PR_GREEN_SHADOW_COUNT, (unsigned long)pid, 0, 0, 0);
}

int green_shadow_make_branch(unsigned long pc, unsigned long target,
                             unsigned char out[4])
{
    unsigned long distance;
    long imm;
    unsigned int insn;

    if ((pc & 3) || (target & 3))
        return -1;

    if (target >= pc) {
        distance = target - pc;
        if (distance > (((1UL << 25) - 1) << 2))
            return -1;
        imm = (long)(distance >> 2);
    } else {
        distance = pc - target;
        if (distance > ((1UL << 25) << 2))
            return -1;
        imm = -(long)(distance >> 2);
    }

    insn = 0x14000000U | ((unsigned int)imm & 0x03ffffffU);
    put_u32_le(out, insn);
    return 0;
}

static void shadow_usage(const char *prog)
{
    fprintf(stderr,
            "Green shadow tool\n\n"
            "Usage:\n"
            "  %s shadow solist  -p <pid>\n"
            "  %s shadow count   -p <pid>\n"
            "  %s shadow patch   -p <pid> (-a <addr>|-b <lib> -o <off>) -x <hex>\n"
            "  %s shadow nop     -p <pid> (-a <addr>|-b <lib> -o <off>) [-n insns]\n"
            "  %s shadow branch  -p <pid> (-a <addr>|-b <lib> -o <off>) -t <target>\n"
            "  %s shadow release -p <pid> [-a <addr>]\n"
            "  %s shadow broker -p <pid>        root-side agent broker\n\n"
            "Notes:\n"
            "  patch/nop/branch write only to the shadow physical page. Reads see original bytes.\n"
            "  release without -a releases all shadow pages in the target mm.\n",
            prog, prog, prog, prog, prog, prog, prog);
}

struct shadow_opts {
    pid_t pid;
    unsigned long addr;
    unsigned long off;
    unsigned long target;
    const char *lib;
    const char *hex;
    int have_addr;
    int have_off;
    int have_target;
    unsigned long nops;
};

static int parse_opts(int argc, char **argv, const char *short_opts,
                      struct shadow_opts *opts)
{
    static struct option long_opts[] = {
        {"pid", required_argument, 0, 'p'},
        {"addr", required_argument, 0, 'a'},
        {"base", required_argument, 0, 'b'},
        {"offset", required_argument, 0, 'o'},
        {"hex", required_argument, 0, 'x'},
        {"target", required_argument, 0, 't'},
        {"num", required_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    int opt;

    memset(opts, 0, sizeof(*opts));
    opts->nops = 1;
    optind = 2;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            if (green_cli_parse_pid(optarg, &opts->pid) < 0)
                return -1;
            break;
        case 'a':
            if (green_cli_parse_ulong(optarg, &opts->addr) < 0)
                return -1;
            opts->have_addr = 1;
            break;
        case 'b':
            opts->lib = optarg;
            break;
        case 'o':
            if (green_cli_parse_ulong(optarg, &opts->off) < 0)
                return -1;
            opts->have_off = 1;
            break;
        case 'x':
            opts->hex = optarg;
            break;
        case 't':
            if (green_cli_parse_ulong(optarg, &opts->target) < 0)
                return -1;
            opts->have_target = 1;
            break;
        case 'n':
            if (green_cli_parse_ulong(optarg, &opts->nops) < 0 || opts->nops == 0)
                return -1;
            break;
        case 'h':
            return 1;
        default:
            return -1;
        }
    }
    return 0;
}

static int resolve_addr(struct shadow_opts *opts)
{
    if (opts->have_addr)
        return 0;
    if (opts->lib && opts->have_off) {
        unsigned long base = green_cli_find_solist(opts->pid, opts->lib);
        if (!base) {
            fprintf(stderr, "library not found in linker64 solist: %s\n", opts->lib);
            return -1;
        }
        opts->addr = base + opts->off;
        opts->have_addr = 1;
        printf("%s base=0x%lx target=0x%lx\n", opts->lib, base, opts->addr);
        return 0;
    }
    fprintf(stderr, "address required: use -a <addr> or -b <lib> -o <offset>\n");
    return -1;
}

static int cmd_solist(int argc, char **argv)
{
    struct shadow_opts opts;
    int ret = parse_opts(argc, argv, "p:h", &opts);

    if (ret > 0) {
        shadow_usage("green");
        return 0;
    }
    if (ret < 0)
        return 1;
    return (int)green_cli_show_exec_solist(opts.pid, NULL);
}

static int cmd_count(int argc, char **argv)
{
    struct shadow_opts opts;
    long ret = parse_opts(argc, argv, "p:h", &opts);

    if (ret > 0) {
        shadow_usage("green");
        return 0;
    }
    if (ret < 0)
        return 1;
    ret = green_shadow_request_count(opts.pid);
    if (ret < 0) {
        fprintf(stderr, "shadow count failed: %s (%ld)\n", strerror((int)-ret), ret);
        return 1;
    }
    printf("%ld\n", ret);
    return 0;
}

static int cmd_patch(int argc, char **argv)
{
    struct shadow_opts opts;
    unsigned char *bytes = NULL;
    size_t len = 0;
    int ret;

    ret = parse_opts(argc, argv, "p:a:b:o:x:h", &opts);
    if (ret != 0) {
        if (ret > 0)
            shadow_usage("green");
        return ret > 0 ? 0 : 1;
    }
    if (resolve_addr(&opts) < 0)
        return 1;
    if (!opts.hex || green_cli_hex_to_bytes(opts.hex, &bytes, &len) < 0) {
        fprintf(stderr, "invalid or missing hex patch\n");
        return 1;
    }

    ret = green_shadow_request_patch(opts.pid, opts.addr, bytes, len);
    if (!ret)
        printf("patched pid=%d addr=0x%lx len=%zu\n",
               green_cli_effective_pid(opts.pid), opts.addr, len);
    green_cli_free(bytes);
    return ret;
}

static int cmd_nop(int argc, char **argv)
{
    struct shadow_opts opts;
    unsigned char *bytes;
    unsigned long i;
    int ret;

    ret = parse_opts(argc, argv, "p:a:b:o:n:h", &opts);
    if (ret != 0) {
        if (ret > 0)
            shadow_usage("green");
        return ret > 0 ? 0 : 1;
    }
    if (resolve_addr(&opts) < 0)
        return 1;
    if (opts.nops > GREEN_SHADOW_MAX_PATCH_LEN / 4) {
        fprintf(stderr, "too many NOP instructions\n");
        return 1;
    }

    bytes = calloc(opts.nops, 4);
    if (!bytes)
        return 1;
    for (i = 0; i < opts.nops; i++)
        put_u32_le(bytes + i * 4, A64_NOP);

    ret = green_shadow_request_patch(opts.pid, opts.addr, bytes, opts.nops * 4);
    if (!ret)
        printf("NOP patched pid=%d addr=0x%lx insns=%lu\n",
               green_cli_effective_pid(opts.pid), opts.addr, opts.nops);
    free(bytes);
    return ret;
}

static int cmd_branch(int argc, char **argv)
{
    struct shadow_opts opts;
    unsigned char bytes[4];
    int ret;

    ret = parse_opts(argc, argv, "p:a:b:o:t:h", &opts);
    if (ret != 0) {
        if (ret > 0)
            shadow_usage("green");
        return ret > 0 ? 0 : 1;
    }
    if (resolve_addr(&opts) < 0)
        return 1;
    if (!opts.have_target || green_shadow_make_branch(opts.addr, opts.target, bytes) < 0) {
        fprintf(stderr, "invalid branch target; B immediate must be 4-byte aligned and within +/-128MB\n");
        return 1;
    }

    ret = green_shadow_request_patch(opts.pid, opts.addr, bytes, sizeof(bytes));
    if (!ret)
        printf("branch patched pid=%d addr=0x%lx target=0x%lx\n",
               green_cli_effective_pid(opts.pid), opts.addr, opts.target);
    return ret;
}

static int cmd_release(int argc, char **argv)
{
    struct shadow_opts opts;
    int ret = parse_opts(argc, argv, "p:a:h", &opts);

    if (ret != 0) {
        if (ret > 0)
            shadow_usage("green");
        return ret > 0 ? 0 : 1;
    }
    return green_shadow_request_release(opts.pid, opts.have_addr ? opts.addr : 0);
}

/*
 * Root-side broker for the injected agent: listens on @green.broker.<pid>
 * and performs the privileged prctl page-table operations on behalf of the
 * target's own agent.  Only peers with the target's uid are served, so a
 * broker instance is bound to exactly one target process.
 */
/* Snapshot the target page cross-process, emit the redirect with the real
 * GumArm64Writer, and commit it through the shadow ABI. */
static int broker_patch(pid_t target, unsigned long target_addr,
                        unsigned long replacement, long *out_value)
{
    unsigned long page = target_addr & ~4095UL;
    size_t offset = (size_t)(target_addr - page);
    static guint8 snapshot[4096];
    struct iovec local = { .iov_base = snapshot, .iov_len = sizeof(snapshot) };
    struct iovec remote = { .iov_base = (void *)page,
                            .iov_len = sizeof(snapshot) };
    GumArm64Writer writer;
    ssize_t n;
    long pr;

    if ((target_addr & 3) || (replacement & 3) || offset > 4096 - 16)
        return -EINVAL;

    do {
        n = process_vm_readv((pid_t)target, &local, 1, &remote, 1, 0);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof(snapshot)) {
        fprintf(stderr, "broker: process_vm_readv failed: %s\n", strerror(errno));
        return -EIO;
    }

    gum_arm64_writer_init(&writer, snapshot + offset);
    writer.pc = (GumAddress)target_addr;
    gum_arm64_writer_put_ldr_reg_address(&writer, ARM64_REG_X16,
                                         (guint64)replacement);
    gum_arm64_writer_put_br_reg(&writer, ARM64_REG_X16);
    gum_arm64_writer_flush(&writer);
    gum_arm64_writer_clear(&writer);

    pr = green_cli_prctl(PR_GREEN_SHADOW_PATCH, target, page,
                         (unsigned long)snapshot, sizeof(snapshot));
    *out_value = pr;
    return pr < 0 ? (int)pr : 0;
}

static int cmd_broker(int argc, char **argv)
{
    struct shadow_opts opts;
    struct sockaddr_un address;
    char name[sizeof(address.sun_path) - 1];
    char status_path[64];
    char line[256];
    unsigned int target_uid = 0;
    int name_len;
    int server;
    FILE *status;
    int ret = parse_opts(argc, argv, "p:h", &opts);

    if (ret != 0) {
        if (ret > 0)
            shadow_usage("green");
        return ret > 0 ? 0 : 1;
    }
    if (opts.pid <= 0) {
        fprintf(stderr, "broker requires --pid <target>\n");
        return 2;
    }

    snprintf(status_path, sizeof(status_path), "/proc/%d/status",
             (int)green_cli_effective_pid(opts.pid));
    status = fopen(status_path, "re");
    if (!status) {
        fprintf(stderr, "cannot open %s\n", status_path);
        return 1;
    }
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "Uid:", 4)) {
            target_uid = (unsigned int)strtoul(line + 4, NULL, 10);
            break;
        }
    }
    fclose(status);

    name_len = green_agent_broker_name(green_cli_effective_pid(opts.pid), name,
                                       sizeof(name));
    if (name_len < 0)
        return 1;
    server = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server < 0) {
        perror("socket");
        return 1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    address.sun_path[0] = '\0';
    memcpy(address.sun_path + 1, name, (size_t)name_len);
    if (bind(server, (struct sockaddr *)&address,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len)) != 0 ||
        listen(server, 4) != 0) {
        perror("bind broker");
        close(server);
        return 1;
    }
    printf("broker ready uid=%u socket=@%s\n", target_uid, name);
    fflush(stdout);

    for (;;) {
        int client = accept(server, NULL, NULL);
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);

        if (client < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0 ||
            cred.uid != (uid_t)target_uid) {
            fprintf(stderr, "broker rejected peer uid=%d\n", (int)cred.uid);
            close(client);
            continue;
        }
        for (;;) {
            struct green_broker_request request;
            struct green_broker_response response;
            unsigned char payload[GREEN_SHADOW_MAX_PATCH_LEN];
            long pr;

            if (read(client, &request, sizeof(request)) != (ssize_t)sizeof(request))
                break;
            memset(&response, 0, sizeof(response));
            if (request.magic != GREEN_AGENT_MAGIC ||
                request.len > GREEN_SHADOW_MAX_PATCH_LEN) {
                response.status = -EBADMSG;
            } else if (request.command == GREEN_BROKER_PATCH) {
                response.status = (int32_t)broker_patch(
                    green_cli_effective_pid(opts.pid), request.addr,
                    request.arg, &response.value);
            } else if (request.command == GREEN_BROKER_RELEASE) {
                pr = green_cli_prctl(PR_GREEN_SHADOW_RELEASE,
                                     green_cli_effective_pid(opts.pid),
                                     request.addr, 0, 0);
                response.status = pr < 0 ? (int32_t)pr : 0;
                response.value = pr;
            } else if (request.command == GREEN_BROKER_COUNT) {
                pr = green_cli_prctl(PR_GREEN_SHADOW_COUNT,
                                     green_cli_effective_pid(opts.pid), 0, 0, 0);
                response.status = pr < 0 ? (int32_t)pr : 0;
                response.value = pr;
            } else {
                response.status = -EOPNOTSUPP;
            }
            if (write(client, &response, sizeof(response)) != (ssize_t)sizeof(response))
                break;
        }
        close(client);
        break;
    }
    close(server);
    return 0;
}

static int shadow_main(int argc, char **argv)
{
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        shadow_usage("green");
        return argc < 2 ? 1 : 0;
    }

    if (!strcmp(argv[1], "solist") || !strcmp(argv[1], "maps"))
        return cmd_solist(argc, argv);
    if (!strcmp(argv[1], "count"))
        return cmd_count(argc, argv);
    if (!strcmp(argv[1], "patch"))
        return cmd_patch(argc, argv);
    if (!strcmp(argv[1], "nop"))
        return cmd_nop(argc, argv);
    if (!strcmp(argv[1], "branch"))
        return cmd_branch(argc, argv);
    if (!strcmp(argv[1], "release"))
        return cmd_release(argc, argv);
    if (!strcmp(argv[1], "broker"))
        return cmd_broker(argc, argv);

    fprintf(stderr, "unknown shadow command: %s\n", argv[1]);
    shadow_usage("green");
    return 1;
}

const struct green_cli_tool green_cli_shadow_tool = {
    .name = "shadow",
    .summary = "shadow-page hidden patch/hook operations",
    .main = shadow_main,
    .usage = shadow_usage,
};
