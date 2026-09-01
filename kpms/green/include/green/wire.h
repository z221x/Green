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
    /* server -> host */
    GREEN_WIRE_LOG = 0x80,    /* log_event */
    GREEN_WIRE_RESULT = 0x81, /* result */
    GREEN_WIRE_PROCS = 0x82,  /* process_list */
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
    int32_t ok;
    uint32_t len;
    /* char msg[len] follows */
};

struct green_wire_proc {
    int32_t pid;
    uint16_t name_len;
    /* char name[name_len] follows */
};

#endif /* GREEN_WIRE_H */
