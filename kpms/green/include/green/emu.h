/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KPM_GREEN_EMU_H_
#define _KPM_GREEN_EMU_H_

#include <ktypes.h>

/*
 * A small, allocation-free AArch64 instruction executor.
 *
 * The executor is deliberately independent of pt_regs.  A caller supplies a
 * register file and memory callbacks, so the same code can be used by the
 * shadow fault path and by future Green tools.  Callbacks must not sleep when
 * the executor is used from an exception hook.
 */
struct green_emu_cpu {
    u64 x[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

typedef int (*green_emu_mem_read_t)(void *ctx, u64 addr, void *buf,
                                    unsigned int size);
typedef int (*green_emu_mem_write_t)(void *ctx, u64 addr, const void *buf,
                                     unsigned int size);

/*
 * SIMD/FP load destination write-back: stores the loaded bytes into the low
 * lanes of V register `reg` (0-31), preserving the upper lanes like the
 * architecture does for B/H/S/D/Q views.  nbytes ∈ {1,2,4,8,16}.
 */
typedef int (*green_emu_simd_write_t)(void *ctx, unsigned int reg,
                                      unsigned int nbytes, const void *data);

struct green_emu_mem {
    void *ctx;
    green_emu_mem_read_t read;
    green_emu_mem_write_t write;

    /* Optional: without it SIMD/FP loads are rejected as unsupported. */
    green_emu_simd_write_t simd_write;

    /* If non-zero, the first memory address must match this fault address. */
    u64 fault_addr;
};

enum green_emu_access {
    GREEN_EMU_ACCESS_NONE = 0,
    GREEN_EMU_ACCESS_READ = 1,
    GREEN_EMU_ACCESS_WRITE = 2,
};

struct green_emu_result {
    u64 address;
    unsigned int size;
    unsigned int access;
    unsigned int reg;
    unsigned int reg2;
    unsigned int writeback;
};

#define GREEN_EMU_OK           0
#define GREEN_EMU_UNSUPPORTED  (-95)
#define GREEN_EMU_BAD_INSN     (-22)
#define GREEN_EMU_BAD_MEMORY   (-14)

/* Execute exactly one AArch64 instruction and advance cpu->pc by four. */
int green_emu_step(struct green_emu_cpu *cpu, u32 insn,
                   const struct green_emu_mem *mem,
                   struct green_emu_result *result);

#endif /* _KPM_GREEN_EMU_H_ */
