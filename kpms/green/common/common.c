/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <green/cli.h>

#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

static const struct green_cli_tool *const green_cli_tools[] = {
    &green_cli_shadow_tool,
};

const struct green_cli_tool *green_cli_find_tool(const char *name)
{
    size_t i;

    if (!name)
        return NULL;
    for (i = 0; i < sizeof(green_cli_tools) / sizeof(green_cli_tools[0]); i++) {
        if (!strcmp(name, green_cli_tools[i]->name))
            return green_cli_tools[i];
    }
    return NULL;
}

void green_cli_global_usage(const char *prog)
{
    size_t i;

    fprintf(stderr, "Green CLI\n\n");
    fprintf(stderr, "Usage:\n  %s <tool> [args...]\n\n", prog);
    fprintf(stderr, "Tools:\n");
    for (i = 0; i < sizeof(green_cli_tools) / sizeof(green_cli_tools[0]); i++)
        fprintf(stderr, "  %-10s %s\n", green_cli_tools[i]->name,
                green_cli_tools[i]->summary);
    fprintf(stderr, "\nUse '%s <tool> --help' for tool-specific help.\n", prog);
}

int green_cli_parse_ulong(const char *s, unsigned long *out)
{
    char *end = NULL;
    unsigned long value;

    if (!s || !*s)
        return -1;
    errno = 0;
    value = strtoul(s, &end, 0);
    if (errno || !end || *end)
        return -1;
    *out = value;
    return 0;
}

int green_cli_parse_pid(const char *s, pid_t *out)
{
    unsigned long value;

    if (green_cli_parse_ulong(s, &value) < 0 || value > 0x7fffffffUL)
        return -1;
    *out = (pid_t)value;
    return 0;
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int green_cli_hex_to_bytes(const char *hex, unsigned char **out, size_t *out_len)
{
    size_t digits = 0;
    size_t i;
    unsigned char *buf;

    if (!hex || !out || !out_len)
        return -1;

    for (i = 0; hex[i]; i++) {
        if (isspace((unsigned char)hex[i]) || hex[i] == ':' || hex[i] == '_')
            continue;
        if (hex_value((unsigned char)hex[i]) < 0)
            return -1;
        digits++;
    }
    if (!digits || (digits & 1))
        return -1;

    buf = malloc(digits / 2);
    if (!buf)
        return -1;

    digits = 0;
    for (i = 0; hex[i];) {
        int hi, lo;

        while (hex[i] && (isspace((unsigned char)hex[i]) || hex[i] == ':' || hex[i] == '_'))
            i++;
        if (!hex[i])
            break;
        hi = hex_value((unsigned char)hex[i++]);
        while (hex[i] && (isspace((unsigned char)hex[i]) || hex[i] == ':' || hex[i] == '_'))
            i++;
        if (!hex[i]) {
            free(buf);
            return -1;
        }
        lo = hex_value((unsigned char)hex[i++]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }
        buf[digits++] = (unsigned char)((hi << 4) | lo);
    }

    *out = buf;
    *out_len = digits;
    return 0;
}

void green_cli_free(void *p)
{
    free(p);
}

long green_cli_prctl(unsigned long option, unsigned long a2, unsigned long a3,
                     unsigned long a4, unsigned long a5)
{
    long ret;

    errno = 0;
    ret = prctl((int)option, a2, a3, a4, a5);
    if (ret < 0)
        return errno ? -errno : ret;
    return ret;
}

pid_t green_cli_effective_pid(pid_t pid)
{
    return pid ? pid : getpid();
}

#define GREEN_LINKER_PATH_MAX 512
#define GREEN_SOLIST_NAME_MAX 512
#define GREEN_SOLIST_MAX_NODES 4096UL
#define GREEN_SOINFO_NEXT_OFFSET 0x28UL
#define GREEN_SOINFO_LINK_MAP_NAME_OFFSET 0xd8UL

struct green_linker_image {
    char path[GREEN_LINKER_PATH_MAX];
    unsigned long base;
};

static FILE *green_cli_open_proc_maps(pid_t pid)
{
    char path[96];

    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/maps");
    else
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    return fopen(path, "r");
}

static int green_cli_is_linker64(const char *path)
{
    const char *name;

    if (!path)
        return 0;
    name = strrchr(path, '/');
    if (!name)
        return 0;
    name++;
    return !strncmp(name, "linker64", 8) &&
           (name[8] == '\0' || name[8] == ' ' || name[8] == '\t');
}

/* Maps is used only to locate linker64; loaded libraries come from solist. */
static int green_cli_find_linker_image(pid_t pid, struct green_linker_image *image)
{
    FILE *fp;
    char line[1024];

    if (!image)
        return -1;
    memset(image, 0, sizeof(*image));

    fp = green_cli_open_proc_maps(pid);
    if (!fp) {
        perror("open linker64 maps");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end, file_offset, inode;
        char perms[8], device[32], path[GREEN_LINKER_PATH_MAX];
        int fields;

        fields = sscanf(line, "%lx-%lx %7s %lx %31s %lu %511[^\n]",
                        &start, &end, perms, &file_offset, device, &inode, path);
        if (fields != 7 || file_offset != 0 || !green_cli_is_linker64(path))
            continue;

        strncpy(image->path, path, sizeof(image->path) - 1);
        image->path[sizeof(image->path) - 1] = '\0';
        {
            char *deleted = strstr(image->path, " (deleted)");
            if (deleted)
                *deleted = '\0';
        }
        image->base = start;
        fclose(fp);
        return 0;
    }

    fclose(fp);
    fprintf(stderr, "linker64 mapping not found for pid %d\n",
            green_cli_effective_pid(pid));
    return -1;
}

static int green_cli_valid_remote_ptr(unsigned long address);

ssize_t green_cli_process_vm_read(pid_t pid, void *local, size_t length,
                                  unsigned long remote)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t count;

    if (!length)
        return 0;
    if (!local || !green_cli_valid_remote_ptr(remote)) {
        errno = EINVAL;
        return -1;
    }

    local_iov.iov_base = local;
    local_iov.iov_len = length;
    remote_iov.iov_base = (void *)remote;
    remote_iov.iov_len = length;
    do {
        count = process_vm_readv(green_cli_effective_pid(pid), &local_iov, 1,
                                 &remote_iov, 1, 0);
    } while (count < 0 && errno == EINTR);
    return count;
}

ssize_t green_cli_process_vm_write(pid_t pid, const void *local, size_t length,
                                   unsigned long remote)
{
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t count;

    if (!length)
        return 0;
    if (!local || !green_cli_valid_remote_ptr(remote)) {
        errno = EINVAL;
        return -1;
    }

    local_iov.iov_base = (void *)local;
    local_iov.iov_len = length;
    remote_iov.iov_base = (void *)remote;
    remote_iov.iov_len = length;
    do {
        count = process_vm_writev(green_cli_effective_pid(pid), &local_iov, 1,
                                  &remote_iov, 1, 0);
    } while (count < 0 && errno == EINTR);
    return count;
}

static int green_cli_read_remote(pid_t pid, unsigned long address,
                                 void *buffer, size_t length)
{
    size_t done = 0;

    while (done < length) {
        ssize_t count;

        if (address > ULONG_MAX - done)
            return -1;
        count = green_cli_process_vm_read(pid, (char *)buffer + done,
                                          length - done, address + done);
        if (count <= 0)
            return -1;
        done += (size_t)count;
    }
    return 0;
}

static int green_cli_read_remote_u64(pid_t pid, unsigned long address,
                                     unsigned long *value)
{
    uint64_t remote_value;

    if (!value || green_cli_read_remote(pid, address, &remote_value,
                                        sizeof(remote_value)) < 0)
        return -1;
    *value = (unsigned long)remote_value;
    return 0;
}

static int green_cli_read_remote_string(pid_t pid, unsigned long address,
                                        char *buffer, size_t length)
{
    size_t i;

    if (!buffer || length < 2)
        return -1;
    for (i = 0; i + 1 < length; i++) {
        unsigned char c;

        if (green_cli_read_remote(pid, address + i, &c, sizeof(c)) < 0)
            return -1;
        if (c == '\0') {
            buffer[i] = '\0';
            return 0;
        }
        if (c < 0x20 || c >= 0x7f)
            return -1;
        buffer[i] = (char)c;
    }
    buffer[length - 1] = '\0';
    return -1;
}

static int green_cli_valid_remote_ptr(unsigned long address)
{
    return address >= 0x1000UL && address < 0x0001000000000000UL;
}

static int green_cli_name_score(const char *name)
{
    int score = 0;

    if (!name || !*name)
        return 0;
    if (name[0] == '/')
        score += 100;
    if (strstr(name, "/"))
        score += 50;
    if (strstr(name, ".so"))
        score += 30;
    if (strstr(name, "linker"))
        score += 20;
    return score;
}

static int green_cli_read_soinfo_name(pid_t pid, unsigned long node,
                                      char *name, size_t name_len,
                                      unsigned long *name_offset)
{
    int best_score = 0;
    unsigned long best_offset = 0;
    char best_name[GREEN_SOLIST_NAME_MAX];
    unsigned long offset;

    if (!name || name_len < 2)
        return -1;

    /* Android 15 arm64 keeps link_map_head.l_name at 0xd8.  Prefer this
     * exact field so entries such as [vdso] are not mistaken for another
     * printable string in the C++ object. */
    if (green_cli_read_remote_u64(pid,
                                  node + GREEN_SOINFO_LINK_MAP_NAME_OFFSET,
                                  &best_offset) == 0 &&
        green_cli_valid_remote_ptr(best_offset) &&
        green_cli_read_remote_string(pid, best_offset, best_name,
                                     sizeof(best_name)) == 0 &&
        best_name[0]) {
        strncpy(name, best_name, name_len - 1);
        name[name_len - 1] = '\0';
        if (name_offset)
            *name_offset = GREEN_SOINFO_LINK_MAP_NAME_OFFSET;
        return 0;
    }

    /* Fallback for older linker layouts with a different link_map offset. */
    best_score = 0;
    for (offset = 0; offset <= 0x400; offset += sizeof(uint64_t)) {
        unsigned long pointer;
        char candidate[GREEN_SOLIST_NAME_MAX];
        int score;

        if (offset == GREEN_SOINFO_LINK_MAP_NAME_OFFSET ||
            green_cli_read_remote_u64(pid, node + offset, &pointer) < 0 ||
            !green_cli_valid_remote_ptr(pointer) ||
            green_cli_read_remote_string(pid, pointer, candidate,
                                         sizeof(candidate)) < 0)
            continue;
        score = green_cli_name_score(candidate);
        if (score > best_score) {
            best_score = score;
            best_offset = offset;
            strncpy(best_name, candidate, sizeof(best_name) - 1);
            best_name[sizeof(best_name) - 1] = '\0';
        }
    }

    if (!best_score)
        return -1;
    strncpy(name, best_name, name_len - 1);
    name[name_len - 1] = '\0';
    if (name_offset)
        *name_offset = best_offset;
    return 0;
}

static int green_cli_find_solist_symbol(const char *path,
                                        unsigned long *symbol_value,
                                        char *symbol_name,
                                        size_t symbol_name_len)
{
    int fd = -1;
    struct stat st;
    unsigned char *file = NULL;
    size_t file_size, done = 0;
    const Elf64_Ehdr *ehdr;
    int best_score = -1;
    uint64_t best_value = 0;
    const char *best_name = NULL;
    unsigned int i;

    if (!path || !symbol_value || !symbol_name || symbol_name_len < 2)
        return -1;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        goto out;
    if (fstat(fd, &st) < 0 || st.st_size <= 0)
        goto out;
    file_size = (size_t)st.st_size;
    file = malloc(file_size);
    if (!file)
        goto out;
    while (done < file_size) {
        ssize_t count = read(fd, file + done, file_size - done);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto out;
        done += (size_t)count;
    }

    if (file_size < sizeof(*ehdr))
        goto out;
    ehdr = (const Elf64_Ehdr *)file;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_shentsize < sizeof(Elf64_Shdr) || !ehdr->e_shnum ||
        ehdr->e_shoff > file_size ||
        ehdr->e_shnum > (file_size - ehdr->e_shoff) / ehdr->e_shentsize)
        goto out;

    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *symtab = (const Elf64_Shdr *)(file + ehdr->e_shoff +
                                                         (size_t)i * ehdr->e_shentsize);
        const Elf64_Shdr *strtab;
        size_t count, j;

        if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM)
            continue;
        if (symtab->sh_entsize < sizeof(Elf64_Sym) ||
            symtab->sh_offset > file_size ||
            symtab->sh_size > file_size - symtab->sh_offset ||
            symtab->sh_link >= ehdr->e_shnum)
            continue;
        strtab = (const Elf64_Shdr *)(file + ehdr->e_shoff +
                                      (size_t)symtab->sh_link * ehdr->e_shentsize);
        if (strtab->sh_offset > file_size ||
            strtab->sh_size > file_size - strtab->sh_offset)
            continue;

        count = (size_t)(symtab->sh_size / symtab->sh_entsize);
        for (j = 0; j < count; j++) {
            const Elf64_Sym *sym = (const Elf64_Sym *)(file + symtab->sh_offset +
                                                       j * symtab->sh_entsize);
            const char *name;
            int score;

            if (sym->st_name >= strtab->sh_size)
                continue;
            name = (const char *)(file + strtab->sh_offset + sym->st_name);
            if (!memchr(name, '\0', strtab->sh_size - sym->st_name) ||
                !strstr(name, "solist"))
                continue;

            score = !strcmp(name, "solist") ? 1000 : 100;
            if (strstr(name, "ZL6solist"))
                score += 500;
            if (ELF64_ST_TYPE(sym->st_info) == STT_OBJECT)
                score += 100;
            if (sym->st_size == sizeof(uint64_t))
                score += 20;
            if (symtab->sh_type == SHT_SYMTAB)
                score += 5;
            if (score > best_score) {
                best_score = score;
                best_value = sym->st_value;
                best_name = name;
            }
        }
    }

    if (best_score < 0 || !best_name || !best_value)
        goto out;
    strncpy(symbol_name, best_name, symbol_name_len - 1);
    symbol_name[symbol_name_len - 1] = '\0';
    *symbol_value = (unsigned long)best_value;
    free(file);
    close(fd);
    return 0;

out:
    free(file);
    if (fd >= 0)
        close(fd);
    return -1;
}

static int green_cli_walk_solist(pid_t pid, const char *needle, int print,
                                 unsigned long *found_base)
{
    struct green_linker_image linker;
    unsigned long solist_symbol, head, node;
    char symbol_name[128];
    unsigned long index;

    if (found_base)
        *found_base = 0;
    if (green_cli_find_linker_image(pid, &linker) < 0)
        return -1;
    if (green_cli_find_solist_symbol(linker.path, &solist_symbol,
                                     symbol_name, sizeof(symbol_name)) < 0) {
        fprintf(stderr, "solist symbol not found in %s\n", linker.path);
        return -1;
    }
    if (linker.base > ULONG_MAX - solist_symbol) {
        fprintf(stderr, "invalid linker64 load address\n");
        return -1;
    }
    solist_symbol += linker.base;

    if (green_cli_read_remote_u64(pid, solist_symbol, &head) < 0 ||
        !green_cli_valid_remote_ptr(head)) {
        fprintf(stderr, "cannot read linker64 solist head at 0x%lx\n", solist_symbol);
        return -1;
    }

    if (print) {
        printf("Loaded libraries from linker64 solist for pid %d:\n",
               green_cli_effective_pid(pid));
        printf("  linker64=0x%lx solist=%s@0x%lx head=0x%lx next_offset=0x%lx\n",
               linker.base, symbol_name, solist_symbol, head,
               GREEN_SOINFO_NEXT_OFFSET);
    }

    node = head;
    for (index = 0; index < GREEN_SOLIST_MAX_NODES; index++) {
        unsigned long next, base, size;
        char name[GREEN_SOLIST_NAME_MAX];
        int have_name;

        if (!green_cli_valid_remote_ptr(node) ||
            green_cli_read_remote_u64(pid, node + GREEN_SOINFO_NEXT_OFFSET, &next) < 0 ||
            green_cli_read_remote_u64(pid, node + 0x10, &base) < 0 ||
            green_cli_read_remote_u64(pid, node + 0x18, &size) < 0) {
            fprintf(stderr, "invalid solist node at 0x%lx\n", node);
            return -1;
        }

        have_name = green_cli_read_soinfo_name(pid, node, name,
                                                sizeof(name), NULL) == 0;
        if (!have_name)
            strcpy(name, "<unnamed>");

        if (have_name && (!needle || strstr(name, needle))) {
            if (found_base)
                *found_base = base;
            if (!print)
                return 0;
        }
        if (print && (!needle || (have_name && strstr(name, needle))))
            printf("  [%04lu] soinfo=0x%lx base=0x%lx size=0x%lx %s\n",
                   index, node, base, size, name);

        if (!next)
            break;
        if (!green_cli_valid_remote_ptr(next) || next == node || next == head) {
            fprintf(stderr, "invalid/cyclic solist next pointer at 0x%lx\n", node);
            return -1;
        }
        node = next;
    }

    if (index == GREEN_SOLIST_MAX_NODES) {
        fprintf(stderr, "solist traversal exceeded %lu nodes\n",
                GREEN_SOLIST_MAX_NODES);
        return -1;
    }
    if (print)
        printf("  total=%lu\n", index + 1);
    return 0;
}

unsigned long green_cli_show_exec_solist(pid_t pid, const char *lib_name)
{
    return green_cli_walk_solist(pid, lib_name, 1, NULL) < 0 ? 1 : 0;
}

unsigned long green_cli_find_solist(pid_t pid, const char *needle)
{
    unsigned long base = 0;

    if (!needle || !*needle || green_cli_walk_solist(pid, needle, 0, &base) < 0)
        return 0;
    return base;
}