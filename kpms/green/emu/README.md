# Green AArch64 emulator

`emu.c` is a small allocation-free, single-instruction executor intended for
exception/fault context. It does not execute arbitrary code and it does not
own a virtual-memory model; callers provide register state and memory
callbacks.

The emulator supports scalar GPR and SIMD/FP memory instructions:

- `LDR`/`STR`, `LDUR`/`STUR`;
- unsigned, signed, register-offset, pre-index and post-index forms;
- `LDRSB`, `LDRSH`, `LDRSW`;
- `LDR` literal;
- `LDP`/`STP` for W/X registers.
- SIMD/FP loads: `LDR Bt/Ht/St/Dt/Qt` (immediate/unscaled/pre/post-index/register-offset), `LDR St/Dt/Qt, literal`, `LDP St/Dt/Qt` pairs; destinations written back through a `simd_write` callback (the shadow fault path writes the live V registers).

Exclusive/atomic instructions, unprivileged accesses and accesses crossing a
page boundary are intentionally rejected. SIMD/FP destinations are written
through the optional `simd_write` callback; the shadow fault hook uses only the
read callback, so a write to a shadow code page still follows the normal
permission-fault path.
