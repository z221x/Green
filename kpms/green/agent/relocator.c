/* Minimal QuickJS binding for frida-gum's ARM64 relocator.  The embedded
 * payload already links Gum's relocator implementation; this file exposes
 * the subset of the Frida Java bridge API used by its ART recompiler. */

#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <quickjs.h>
#include <capstone.h>
#include "arch-arm64/gumarm64writer.h"
#include "arch-arm64/gumarm64relocator.h"

#define GREEN_MAX_R 64

extern GumArm64Writer *green_a64w_get(int h);

static GumArm64Relocator *g_relocators[GREEN_MAX_R];
static const cs_insn *g_inputs[GREEN_MAX_R];

static int js_to_u64(JSContext *ctx, JSValueConst value, uint64_t *out)
{
    JSValue iv = JS_DupValue(ctx, value);
    int result = -1;

    if (JS_IsObject(iv)) {
        JSValue inner = JS_GetPropertyStr(ctx, iv, "__v");
        if (!JS_IsUndefined(inner) && !JS_IsException(inner)) {
            JS_FreeValue(ctx, iv);
            iv = inner;
        } else {
            JS_FreeValue(ctx, inner);
        }
    }
    if (JS_IsBigInt(ctx, iv)) {
        int64_t n = 0;
        if (JS_ToBigInt64(ctx, &n, iv) == 0) {
            *out = (uint64_t)n;
            result = 0;
        }
    } else {
        int64_t n = 0;
        if (JS_ToInt64(ctx, &n, iv) == 0) {
            *out = (uint64_t)n;
            result = 0;
        }
    }
    JS_FreeValue(ctx, iv);
    return result;
}

static GumArm64Relocator *r_get(int h)
{
    return (h >= 0 && h < GREEN_MAX_R) ? g_relocators[h] : NULL;
}

static void r_dispose(int h)
{
    GumArm64Relocator *r = r_get(h);
    if (r != NULL)
        gum_arm64_relocator_unref(r);
    if (h >= 0 && h < GREEN_MAX_R) {
        g_relocators[h] = NULL;
        g_inputs[h] = NULL;
    }
}

static JSValue js_relocator_new(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    uint64_t input = 0;
    int wh = -1;
    GumArm64Writer *writer;
    GumArm64Relocator *r;
    int h;

    (void)this_val;
    if (argc < 2 || js_to_u64(ctx, argv[0], &input) != 0 ||
        JS_ToInt32(ctx, &wh, argv[1]) != 0 ||
        (writer = green_a64w_get(wh)) == NULL)
        return JS_ThrowInternalError(ctx, "a64r_new(input, writer)");
    for (h = 0; h < GREEN_MAX_R; h++)
        if (g_relocators[h] == NULL)
            break;
    if (h == GREEN_MAX_R)
        return JS_ThrowInternalError(ctx, "too many relocators");
    r = gum_arm64_relocator_new((gconstpointer)(uintptr_t)input, writer);
    if (r == NULL)
        return JS_ThrowInternalError(ctx, "cannot create ARM64 relocator");
    g_relocators[h] = r;
    g_inputs[h] = NULL;
    return JS_NewInt32(ctx, h);
}

static JSValue make_reg_array(JSContext *ctx, const uint16_t *regs,
                              uint8_t count, csh capstone)
{
    JSValue result = JS_NewArray(ctx);
    uint8_t i;

    for (i = 0; i < count; i++) {
        const char *name = cs_reg_name(capstone, regs[i]);
        JS_SetPropertyUint32(ctx, result, i,
            JS_NewString(ctx, name != NULL ? name : "?"));
    }
    return result;
}

static JSValue make_operand(JSContext *ctx, const cs_arm64_op *operand,
                            csh capstone)
{
    JSValue result = JS_NewObject(ctx);

    switch (operand->type) {
    case ARM64_OP_REG: {
        const char *name = cs_reg_name(capstone, operand->reg);
        JS_SetPropertyStr(ctx, result, "type", JS_NewString(ctx, "reg"));
        JS_SetPropertyStr(ctx, result, "value",
            JS_NewString(ctx, name != NULL ? name : "?"));
        break;
    }
    case ARM64_OP_IMM:
        JS_SetPropertyStr(ctx, result, "type", JS_NewString(ctx, "imm"));
        JS_SetPropertyStr(ctx, result, "value",
            JS_NewInt64(ctx, (int64_t)operand->imm));
        break;
    case ARM64_OP_MEM: {
        JSValue mem = JS_NewObject(ctx);
        const char *base = cs_reg_name(capstone, operand->mem.base);
        const char *index = cs_reg_name(capstone, operand->mem.index);
        JS_SetPropertyStr(ctx, result, "type", JS_NewString(ctx, "mem"));
        JS_SetPropertyStr(ctx, mem, "base",
            JS_NewString(ctx, base != NULL ? base : ""));
        JS_SetPropertyStr(ctx, mem, "index",
            JS_NewString(ctx, index != NULL ? index : ""));
        JS_SetPropertyStr(ctx, mem, "scale", JS_NewInt32(ctx, 1));
        JS_SetPropertyStr(ctx, mem, "disp",
            JS_NewInt64(ctx, (int64_t)operand->mem.disp));
        JS_SetPropertyStr(ctx, result, "value", mem);
        break;
    }
    default:
        JS_SetPropertyStr(ctx, result, "type", JS_NewString(ctx, "imm"));
        JS_SetPropertyStr(ctx, result, "value", JS_NewInt32(ctx, 0));
        break;
    }
    return result;
}

static JSValue make_instruction(JSContext *ctx, const cs_insn *insn,
                                csh capstone)
{
    JSValue result, operands, accessed;
    uint8_t i;

    if (insn == NULL)
        return JS_NULL;
    result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "address",
        JS_NewInt64(ctx, (int64_t)insn->address));
    JS_SetPropertyStr(ctx, result, "next",
        JS_NewInt64(ctx, (int64_t)(insn->address + insn->size)));
    JS_SetPropertyStr(ctx, result, "size",
        JS_NewInt32(ctx, (int)insn->size));
    JS_SetPropertyStr(ctx, result, "mnemonic",
        JS_NewString(ctx, insn->mnemonic));
    JS_SetPropertyStr(ctx, result, "op_str",
        JS_NewString(ctx, insn->op_str));

    operands = JS_NewArray(ctx);
    if (insn->detail != NULL) {
        const cs_arm64 *detail = &insn->detail->arm64;
        for (i = 0; i < detail->op_count; i++)
            JS_SetPropertyUint32(ctx, operands, i,
                make_operand(ctx, &detail->operands[i], capstone));
    }
    JS_SetPropertyStr(ctx, result, "operands", operands);

    accessed = JS_NewObject(ctx);
    if (insn->detail != NULL) {
        JS_SetPropertyStr(ctx, accessed, "read",
            make_reg_array(ctx, insn->detail->regs_read,
                           insn->detail->regs_read_count, capstone));
        JS_SetPropertyStr(ctx, accessed, "written",
            make_reg_array(ctx, insn->detail->regs_write,
                           insn->detail->regs_write_count, capstone));
    } else {
        JS_SetPropertyStr(ctx, accessed, "read", JS_NewArray(ctx));
        JS_SetPropertyStr(ctx, accessed, "written", JS_NewArray(ctx));
    }
    JS_SetPropertyStr(ctx, result, "regsAccessed", accessed);
    return result;
}

static JSValue js_relocator_input(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv)
{
    int h;
    (void)this_val;
    if (argc < 1 || JS_ToInt32(ctx, &h, argv[0]) != 0)
        return JS_NULL;
    return make_instruction(ctx, (h >= 0 && h < GREEN_MAX_R) ? g_inputs[h] : NULL,
                            r_get(h) != NULL ? r_get(h)->capstone : 0);
}

static JSValue js_relocator_op(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv)
{
    int h, op;
    GumArm64Relocator *r;
    (void)this_val;
    if (argc < 2 || JS_ToInt32(ctx, &h, argv[0]) != 0 ||
        JS_ToInt32(ctx, &op, argv[1]) != 0 || (r = r_get(h)) == NULL)
        return JS_ThrowInternalError(ctx, "invalid ARM64 relocator");
    switch (op) {
    case 1: {
        const cs_insn *insn = NULL;
        guint n = gum_arm64_relocator_read_one(r, &insn);
        g_inputs[h] = insn;
        return JS_NewInt32(ctx, (int)n);
    }
    case 2:
        gum_arm64_relocator_write_all(r);
        return JS_UNDEFINED;
    case 3:
        gum_arm64_relocator_skip_one(r);
        return JS_UNDEFINED;
    case 4:
        return JS_NewBool(ctx, gum_arm64_relocator_write_one(r));
    case 5:
        r_dispose(h);
        return JS_UNDEFINED;
    case 6:
        return JS_NewBool(ctx, gum_arm64_relocator_eoi(r));
    case 7:
        return JS_NewBool(ctx, gum_arm64_relocator_eob(r));
    default:
        return JS_UNDEFINED;
    }
}

void green_relocator_register_natives(JSContext *ctx, JSValue global)
{
    JS_SetPropertyStr(ctx, global, "__green_a64r_new",
        JS_NewCFunction(ctx, js_relocator_new, "__green_a64r_new", 2));
    JS_SetPropertyStr(ctx, global, "__green_a64r_input",
        JS_NewCFunction(ctx, js_relocator_input, "__green_a64r_input", 1));
    JS_SetPropertyStr(ctx, global, "__green_a64r",
        JS_NewCFunction(ctx, js_relocator_op, "__green_a64r", 2));
}
