/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef GREEN_WIRE_H
#define GREEN_WIRE_H

#include <stdint.h>

/* Wire protocol between the host CLI (Python) and the on-device
 * `green server` daemon.  TCP, little-endian, length-prefixed frames:
 *
 *   u32 magic ("GGR1"), u16 type, u16 flags, u32 payload_len, payload
 */

#define GREEN_WIRE_MAGIC 0x31524747u
#define GREEN_WIRE_DEFAULT_PORT 27042

enum green_wire_type {
    /* host -> server */
    GREEN_WIRE_LIST = 1,   /* no payload */
    GREEN_WIRE_ATTACH = 2, /* attach_request */
    GREEN_WIRE_SPAWN = 3,  /* spawn_request */
    GREEN_WIRE_SHADOW_PATCH = 4,   /* shadow_patch: raw hidden patch */
    GREEN_WIRE_SHADOW_RELEASE = 5, /* shadow_release */
    GREEN_WIRE_SHADOW_COUNT = 6,   /* shadow_count */
    GREEN_WIRE_SOLIST = 7,         /* solist request */
    GREEN_WIRE_EVAL = 8,           /* eval: {i32 pid, u32 code_len, code} */
    GREEN_WIRE_KILL = 9,           /* kill: {i32 pid} */
    /* server -> host */
    GREEN_WIRE_LOG = 0x80,    /* log_event */
    GREEN_WIRE_RESULT = 0x81, /* result (ok + value + message) */
    GREEN_WIRE_PROCS = 0x82,  /* process_list */
    GREEN_WIRE_MODULES = 0x83, /* module_list (solist) */
};

struct green_wire_shadow_patch {
    int32_t pid;
    uint32_t len;
    uint64_t addr;
    /* unsigned char bytes[len] follows (len <= 4096) */
};

struct green_wire_shadow_release {
    int32_t pid;
    uint32_t reserved;
    uint64_t addr; /* 0 = release every shadow page of the mm */
};

struct green_wire_solist {
    int32_t pid;
    uint8_t has_name;
    char name[128];
};


struct green_wire_frame {
    uint32_t magic;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
};

struct green_wire_attach {
    int32_t pid;               /* used when has_package == 0 */
    uint8_t has_package;
    char package[128];
    uint32_t script_len;
    /* unsigned char script[script_len] follows */
};

struct green_wire_log {
    int32_t pid;
    uint32_t len;
    /* char text[len] follows */
};

struct green_wire_result {
    int32_t ok;    /* 0 on failure; 1 on success (result value in `value`) */
    int64_t value; /* command-specific (e.g. released page count) */
    uint32_t len;
    /* char msg[len] follows */
};

struct green_wire_proc {
    int32_t pid;
    uint16_t name_len;
    /* char name[name_len] follows */
};

#endif /* GREEN_WIRE_H */
