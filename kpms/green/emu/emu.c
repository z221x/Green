/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <green/emu.h>
#include <linux/string.h>

#define GREEN_EMU_BIT(n) (1U << (n))

#define GREEN_EMU_LS_CLASS       0x38000000U
#define GREEN_EMU_LS_CLASS_MASK  0x3b000000U
#define GREEN_EMU_LS_IMM_CLASS   0x39000000U
#define GREEN_EMU_LS_IMM_MASK    0x3b800000U
#define GREEN_EMU_PAIR_CLASS     0x28000000U
#define GREEN_EMU_PAIR_MASK      0x3a000000U
#define GREEN_EMU_LITERAL_CLASS  0x18000000U

#define GREEN_EMU_MODE_OFFSET 0
#define GREEN_EMU_MODE_POST   1
#define GREEN_EMU_MODE_PRE    3

#define GREEN_EMU_KIND_SCALAR 1
#define GREEN_EMU_KIND_PAIR   2
#define GREEN_EMU_KIND_LITERAL 3

struct green_emu_decoded {
    unsigned int kind;
    unsigned int load;
    unsigned int sign;
    unsigned int size;
    unsigned int dst_bits;
    unsigned int rt;
    unsigned int rt2;
    unsigned int rn;
    unsigned int rm;
    unsigned int option;
    unsigned int shift;
    unsigned int mode;
    unsigned int writeback;
    unsigned int reg_offset;
    s64 offset;
};

static s64 green_emu_sext(u64 value, unsigned int bits)
{
    u64 sign;

    sign = 1ULL << (bits - 1);
    return (s64)((value ^ sign) - sign);
}

static u64 green_emu_read_reg(const struct green_emu_cpu *cpu,
                              unsigned int reg)
{
    if (reg >= 31)
        return 0;
    return cpu->x[reg];
}

static u64 green_emu_read_base(const struct green_emu_cpu *cpu,
                               unsigned int reg)
{
    if (reg >= 31)
        return cpu->sp;
    return cpu->x[reg];
}

static void green_emu_write_reg(struct green_emu_cpu *cpu, unsigned int reg,
                                u64 value, unsigned int bits)
{
    if (reg >= 31)
        return;
    cpu->x[reg] = bits == 32 ? (u64)(u32)value : value;
}

static void green_emu_write_base(struct green_emu_cpu *cpu, unsigned int reg,
                                 u64 value)
{
    if (reg >= 31)
        cpu->sp = value;
    else
        cpu->x[reg] = value;
}

static u64 green_emu_load_le(const u8 *data, unsigned int size)
{
    u64 value = 0;
    unsigned int i;

    for (i = 0; i < size; i++)
        value |= (u64)data[i] << (i * 8);
    return value;
}

static void green_emu_store_le(u8 *data, unsigned int size, u64 value)
{
    unsigned int i;

    for (i = 0; i < size; i++)
        data[i] = (u8)(value >> (i * 8));
}

static int green_emu_decode_scalar_imm(u32 insn,
                                       struct green_emu_decoded *d)
{
    unsigned int op = (insn >> 22) & 3;
    unsigned int size_code = (insn >> 30) & 3;

    if (insn & GREEN_EMU_BIT(26))
        return GREEN_EMU_UNSUPPORTED;

    d->kind = GREEN_EMU_KIND_SCALAR;
    d->rt = insn & 31;
    d->rn = (insn >> 5) & 31;
    d->mode = GREEN_EMU_MODE_OFFSET;
    d->writeback = 0;
    d->reg_offset = 0;
    d->offset = (s64)((u64)((insn >> 10) & 0xfff) << size_code);

    if (op == 0 || op == 1) {
        d->load = op == 1;
        d->sign = 0;
        d->size = 1U << size_code;
        d->dst_bits = size_code == 3 ? 64 : 32;
        return GREEN_EMU_OK;
    }

    /* LDRSB/LDRSH/LDRSW, with either a W or X destination. */
    if (size_code > 2)
        return GREEN_EMU_UNSUPPORTED;
    d->load = 1;
    d->sign = 1;
    d->size = 1U << size_code;
    d->dst_bits = op == 3 ? 32 : 64;
    return GREEN_EMU_OK;
}

static int green_emu_decode_scalar(u32 insn, struct green_emu_decoded *d)
{
    unsigned int op;
    unsigned int size_code;
    unsigned int mode;
    unsigned int option;

    if ((insn & GREEN_EMU_LS_IMM_MASK) == GREEN_EMU_LS_IMM_CLASS ||
        (insn & GREEN_EMU_LS_IMM_MASK) == (GREEN_EMU_LS_IMM_CLASS | 0x00800000U))
        return green_emu_decode_scalar_imm(insn, d);

    if ((insn & GREEN_EMU_LS_CLASS_MASK) != GREEN_EMU_LS_CLASS)
        return GREEN_EMU_UNSUPPORTED;

    /* Bit 26 selects the SIMD/FP form, which is not in the first subset. */
    if (insn & GREEN_EMU_BIT(26))
        return GREEN_EMU_UNSUPPORTED;

    op = (insn >> 22) & 3;
    size_code = (insn >> 30) & 3;
    d->kind = GREEN_EMU_KIND_SCALAR;
    d->rt = insn & 31;
    d->rn = (insn >> 5) & 31;
    d->writeback = 0;
    d->reg_offset = 0;
    d->offset = 0;

    /* Bit 21 selects the register-offset form. */
    if (insn & GREEN_EMU_BIT(21)) {
        option = (insn >> 13) & 7;
        if (option != 2 && option != 3 && option != 6 && option != 7)
            return GREEN_EMU_UNSUPPORTED;
        if (((insn >> 12) & 1) && size_code == 0)
            return GREEN_EMU_UNSUPPORTED;

        d->reg_offset = 1;
        d->rm = (insn >> 16) & 31;
        d->option = option;
        d->shift = (insn >> 12) & 1;
    } else {
        mode = (insn >> 10) & 3;
        /* 10 is the unprivileged LDTR/STTR form. */
        if (mode == 2)
            return GREEN_EMU_UNSUPPORTED;
        d->mode = mode;
        if (mode != GREEN_EMU_MODE_OFFSET) {
            d->writeback = 1;
            d->offset = green_emu_sext((insn >> 12) & 0x1ff, 9);
        } else {
            d->offset = green_emu_sext((insn >> 12) & 0x1ff, 9);
        }
    }

    if (op == 0 || op == 1) {
        d->load = op == 1;
        d->sign = 0;
        d->size = 1U << size_code;
        d->dst_bits = size_code == 3 ? 64 : 32;
        return GREEN_EMU_OK;
    }

    /* Register/unscaled signed loads: LDRSB/LDRSH/LDRSW. */
    if (size_code > 2)
        return GREEN_EMU_UNSUPPORTED;
    d->load = 1;
    d->sign = 1;
    d->size = 1U << size_code;
    d->dst_bits = op == 3 ? 32 : 64;
    return GREEN_EMU_OK;
}

static int green_emu_decode_pair(u32 insn, struct green_emu_decoded *d)
{
    unsigned int mode;
    unsigned int size;

    if ((insn & GREEN_EMU_PAIR_MASK) != GREEN_EMU_PAIR_CLASS)
        return GREEN_EMU_UNSUPPORTED;
    if (insn & GREEN_EMU_BIT(26))
        return GREEN_EMU_UNSUPPORTED;

    /* GPR pair instructions use size 00 (W) or 10 (X). */
    if ((insn >> 30) & 1)
        return GREEN_EMU_UNSUPPORTED;
    size = (insn & GREEN_EMU_BIT(31)) ? 8 : 4;

    mode = (insn >> 23) & 3;
    /* Mode 00 is LDNP/STNP.  Keep the first implementation conservative. */
    if (mode == 0)
        return GREEN_EMU_UNSUPPORTED;

    d->kind = GREEN_EMU_KIND_PAIR;
    d->load = (insn >> 22) & 1;
    d->sign = 0;
    d->size = size;
    d->dst_bits = size * 8;
    d->rt = insn & 31;
    d->rt2 = (insn >> 10) & 31;
    d->rn = (insn >> 5) & 31;
    d->mode = mode;
    d->writeback = mode != 2;
    d->reg_offset = 0;
    d->offset = green_emu_sext((insn >> 15) & 0x7f, 7) * (s64)size;
    return GREEN_EMU_OK;
}

static int green_emu_decode_literal(u32 insn, struct green_emu_decoded *d)
{
    unsigned int size_code = (insn >> 30) & 3;

    if ((insn & GREEN_EMU_LS_CLASS_MASK) != GREEN_EMU_LITERAL_CLASS)
        return GREEN_EMU_UNSUPPORTED;
    if (insn & GREEN_EMU_BIT(26))
        return GREEN_EMU_UNSUPPORTED;
    if (size_code == 3)
        return GREEN_EMU_UNSUPPORTED; /* PRFM literal. */

    d->kind = GREEN_EMU_KIND_LITERAL;
    d->load = 1;
    d->sign = size_code == 2;
    d->size = size_code == 1 ? 8 : 4;
    d->dst_bits = size_code == 2 ? 64 : (size_code == 1 ? 64 : 32);
    d->rt = insn & 31;
    d->rn = 0;
    d->writeback = 0;
    d->reg_offset = 0;
    d->offset = green_emu_sext((insn >> 5) & 0x7ffff, 19) * (s64)4;
    return GREEN_EMU_OK;
}

static int green_emu_decode(u32 insn, struct green_emu_decoded *d)
{
    int ret;

    memset(d, 0, sizeof(*d));

    ret = green_emu_decode_scalar(insn, d);
    if (ret == GREEN_EMU_OK)
        return ret;
    ret = green_emu_decode_pair(insn, d);
    if (ret == GREEN_EMU_OK)
        return ret;
    ret = green_emu_decode_literal(insn, d);
    if (ret == GREEN_EMU_OK)
        return ret;
    return GREEN_EMU_UNSUPPORTED;
}

static u64 green_emu_index(const struct green_emu_cpu *cpu,
                           const struct green_emu_decoded *d)
{
    u64 value = green_emu_read_reg(cpu, d->rm);
    s64 signed_value;
    unsigned int amount = d->shift ? (d->size == 8 ? 3 :
                                      d->size == 4 ? 2 :
                                      d->size == 2 ? 1 : 0) : 0;

    switch (d->option) {
    case 2: /* UXTW */
        value = (u64)(u32)value;
        break;
    case 3: /* UXTX / LSL */
        break;
    case 6: /* SXTW */
        signed_value = (s64)(s32)(u32)value;
        value = (u64)signed_value;
        break;
    case 7: /* SXTX */
        break;
    default:
        return 0;
    }
    return value << amount;
}

static u64 green_emu_address(const struct green_emu_cpu *cpu,
                             const struct green_emu_decoded *d)
{
    u64 base;

    if (d->kind == GREEN_EMU_KIND_LITERAL)
        return cpu->pc + (u64)d->offset;

    base = green_emu_read_base(cpu, d->rn);
    if (d->reg_offset)
        return base + green_emu_index(cpu, d);
    if (d->mode == GREEN_EMU_MODE_PRE)
        return base + (u64)d->offset;
    return base;
}

static u64 green_emu_writeback_address(const struct green_emu_cpu *cpu,
                                       const struct green_emu_decoded *d)
{
    u64 base = green_emu_read_base(cpu, d->rn);

    return base + (u64)d->offset;
}

static int green_emu_check_fault_address(const struct green_emu_mem *mem,
                                         u64 address)
{
    if (mem->fault_addr && mem->fault_addr != address)
        return GREEN_EMU_BAD_MEMORY;
    return GREEN_EMU_OK;
}

int green_emu_step(struct green_emu_cpu *cpu, u32 insn,
                   const struct green_emu_mem *mem,
                   struct green_emu_result *result)
{
    struct green_emu_cpu next;
    struct green_emu_decoded d;
    struct green_emu_result out;
    u8 data[16];
    u64 address;
    u64 value;
    u64 value2;
    int ret;

    if (!cpu || !mem)
        return GREEN_EMU_BAD_INSN;

    ret = green_emu_decode(insn, &d);
    if (ret)
        return ret;
    if (d.size == 0 || d.size > 8)
        return GREEN_EMU_UNSUPPORTED;
    if (d.kind == GREEN_EMU_KIND_PAIR && d.size * 2 > sizeof(data))
        return GREEN_EMU_UNSUPPORTED;
    if (!d.load && !mem->write)
        return GREEN_EMU_BAD_MEMORY;
    if (d.load && !mem->read)
        return GREEN_EMU_BAD_MEMORY;

    /* Writeback overlap has architecturally constrained/unpredictable cases. */
    if (d.writeback && d.load && d.rn < 31 &&
        (d.rn == d.rt || (d.kind == GREEN_EMU_KIND_PAIR && d.rn == d.rt2)))
        return GREEN_EMU_UNSUPPORTED;
    if (d.kind == GREEN_EMU_KIND_PAIR && d.load && d.rt == d.rt2)
        return GREEN_EMU_UNSUPPORTED;

    address = green_emu_address(cpu, &d);
    ret = green_emu_check_fault_address(mem, address);
    if (ret)
        return ret;

    if (d.kind == GREEN_EMU_KIND_PAIR) {
        if (d.load)
            ret = mem->read(mem->ctx, address, data, d.size * 2);
        else {
            green_emu_store_le(data, d.size, green_emu_read_reg(cpu, d.rt));
            green_emu_store_le(data + d.size, d.size,
                               green_emu_read_reg(cpu, d.rt2));
            ret = mem->write(mem->ctx, address, data, d.size * 2);
        }
    } else if (d.load) {
        ret = mem->read(mem->ctx, address, data, d.size);
    } else {
        green_emu_store_le(data, d.size, green_emu_read_reg(cpu, d.rt));
        ret = mem->write(mem->ctx, address, data, d.size);
    }
    if (ret)
        return ret;

    next = *cpu;
    if (d.load) {
        value = green_emu_load_le(data, d.size);
        if (d.sign)
            value = (u64)green_emu_sext(value, d.size * 8);
        green_emu_write_reg(&next, d.rt, value, d.dst_bits);
        if (d.kind == GREEN_EMU_KIND_PAIR) {
            value2 = green_emu_load_le(data + d.size, d.size);
            green_emu_write_reg(&next, d.rt2, value2, d.dst_bits);
        }
    }
    if (d.writeback)
        green_emu_write_base(&next, d.rn,
                             d.mode == GREEN_EMU_MODE_PRE ? address :
                             green_emu_writeback_address(cpu, &d));
    next.pc = cpu->pc + 4;

    out.address = address;
    out.size = d.size * (d.kind == GREEN_EMU_KIND_PAIR ? 2 : 1);
    out.access = d.load ? GREEN_EMU_ACCESS_READ : GREEN_EMU_ACCESS_WRITE;
    out.reg = d.rt;
    out.reg2 = d.kind == GREEN_EMU_KIND_PAIR ? d.rt2 : 0;
    out.writeback = d.writeback;

    *cpu = next;
    if (result)
        *result = out;
    return GREEN_EMU_OK;
}
