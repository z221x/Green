/* Arm64Writer JS binding over frida-gum's C API — the subset of methods
 * used by frida-java-bridge's machine-code generation. */

#include <string.h>
#include <glib.h>
#include "arch-arm64/gumarm64writer.h"
#include <quickjs.h>

#define GREEN_MAX_W 16
static GumArm64Writer g_writers[GREEN_MAX_W];
static int g_writer_used[GREEN_MAX_W];

static const struct { const char *name; arm64_reg reg; } kRegs[] = {
    { "x0", ARM64_REG_X0 }, { "x1", ARM64_REG_X1 }, { "x2", ARM64_REG_X2 },
    { "x3", ARM64_REG_X3 }, { "x4", ARM64_REG_X4 }, { "x5", ARM64_REG_X5 },
    { "x6", ARM64_REG_X6 }, { "x7", ARM64_REG_X7 }, { "x8", ARM64_REG_X8 },
    { "x9", ARM64_REG_X9 }, { "x10", ARM64_REG_X10 }, { "x11", ARM64_REG_X11 },
    { "x12", ARM64_REG_X12 }, { "x13", ARM64_REG_X13 },
    { "x14", ARM64_REG_X14 }, { "x15", ARM64_REG_X15 },
    { "x16", ARM64_REG_X16 }, { "x17", ARM64_REG_X17 },
    { "x18", ARM64_REG_X18 }, { "x19", ARM64_REG_X19 },
    { "x20", ARM64_REG_X20 }, { "x21", ARM64_REG_X21 },
    { "x22", ARM64_REG_X22 }, { "x23", ARM64_REG_X23 },
    { "x24", ARM64_REG_X24 }, { "x25", ARM64_REG_X25 },
    { "x26", ARM64_REG_X26 }, { "x27", ARM64_REG_X27 },
    { "x28", ARM64_REG_X28 }, { "x29", ARM64_REG_X29 }, { "x30", ARM64_REG_X30 },
    { "lr", ARM64_REG_X30 }, { "sp", ARM64_REG_SP }, { "fp", ARM64_REG_X29 },
    { "xzr", ARM64_REG_XZR }, { "wzr", ARM64_REG_WZR },
    { "w0", ARM64_REG_W0 }, { "w1", ARM64_REG_W1 }, { "w2", ARM64_REG_W2 },
    { "w3", ARM64_REG_W3 }, { "w4", ARM64_REG_W4 }, { "w5", ARM64_REG_W5 },
    { "w6", ARM64_REG_W6 }, { "w7", ARM64_REG_W7 },
    { "s0", ARM64_REG_S0 }, { "s1", ARM64_REG_S1 }, { "d0", ARM64_REG_D0 },
    { "d1", ARM64_REG_D1 }, { "q0", ARM64_REG_Q0 }, { "q1", ARM64_REG_Q1 },
    { NULL, ARM64_REG_INVALID },
};



static arm64_reg parse_reg(JSContext *ctx, JSValueConst v)
{
    const char *s = JS_ToCString(ctx, v);
    const struct { const char *name; arm64_reg reg; } *p;
    if (s == NULL)
        return ARM64_REG_INVALID;
    for (p = kRegs; p->name != NULL; p++) {
        if (strcmp(p->name, s) == 0) {
            JS_FreeCString(ctx, s);
            return p->reg;
        }
    }
    JS_FreeCString(ctx, s);
    return ARM64_REG_INVALID;
}

static GumArm64Writer *w_get(int h)
{
    return (h >= 0 && h < GREEN_MAX_W && g_writer_used[h]) ? &g_writers[h] : NULL;
}

/* __green_a64w_new(codePtr) -> handle */
static JSValue js_a64w_new(JSContext *ctx, JSValueConst this_val,
                           int argc, JSValueConst *argv)
{
    uint64_t code = 0;
    int h;

    (void)this_val;
    if (argc < 1 || JS_ToInt64(ctx, (int64_t *)&code, argv[0]) != 0)
        return JS_ThrowInternalError(ctx, "a64w_new(code)");
    for (h = 0; h < GREEN_MAX_W; h++)
        if (!g_writer_used[h])
            break;
    if (h == GREEN_MAX_W)
        return JS_ThrowInternalError(ctx, "too many writers");
    gum_arm64_writer_init(&g_writers[h], (gpointer)(uintptr_t)code);
    g_writer_used[h] = 1;
    return JS_NewInt32(ctx, h);
}

/* Generic dispatch: __green_a64w(h, op, a, b, c, d) */
static JSValue js_a64w(JSContext *ctx, JSValueConst this_val, int argc,
                       JSValueConst *argv)
{
    GumArm64Writer *w;
    int64_t a0 = 0, a1 = 0, a2 = 0, a3 = 0;
    int h, op;
    JSValue el;

    (void)this_val;
    if (argc < 2)
        return JS_UNDEFINED;
    JS_ToInt32(ctx, &h, argv[0]);
    JS_ToInt32(ctx, &op, argv[1]);
    w = w_get(h);
    if (w == NULL)
        return JS_UNDEFINED;
    if (argc > 2) JS_ToInt64(ctx, &a0, argv[2]);
    if (argc > 3) JS_ToInt64(ctx, &a1, argv[3]);
    if (argc > 4) JS_ToInt64(ctx, &a2, argv[4]);
    if (argc > 5) JS_ToInt64(ctx, &a3, argv[5]);

    switch (op) {
    case 1: gum_arm64_writer_put_push_reg_reg(w, (arm64_reg)a0, (arm64_reg)a1); break;
    case 2: gum_arm64_writer_put_pop_reg_reg(w, (arm64_reg)a0, (arm64_reg)a1); break;
    case 3: gum_arm64_writer_put_label(w, (gconstpointer)(uintptr_t)a0); break;
    case 4: gum_arm64_writer_put_b_cond_label(w, (arm64_cc)a0, (gconstpointer)(uintptr_t)a1); break;
    case 5: gum_arm64_writer_put_ldr_reg_address(w, (arm64_reg)a0, (guint64)a1); break;
    case 6: gum_arm64_writer_put_str_reg_reg_offset(w, (arm64_reg)a0,
                (arm64_reg)a1, (gint8)a2); break;
    case 7: gum_arm64_writer_put_ldr_reg_reg_offset(w, (arm64_reg)a0,
                (arm64_reg)a1, (gint)a2); break;
    case 8: gum_arm64_writer_put_mov_reg_reg(w, (arm64_reg)a0, (arm64_reg)a1); break;
    case 9: gum_arm64_writer_put_ldr_reg_reg_offset(w, (arm64_reg)a0,
                (arm64_reg)a1, (gint)a2); break;  /* MovRegRegOffsetPtr */
    case 10: gum_arm64_writer_put_ret(w); break;
    case 11: gum_arm64_writer_put_br_reg(w, (arm64_reg)a0); break;
    case 12: {  /* putPushRegs(list of regs) — stp pairs, odd tail pushed alone */
        arm64_reg regs[32];
        int n = 0, i;
        uint32_t lu = 0;
        JSValue lv;
        if (!JS_IsArray(ctx, argv[2]))
            return JS_UNDEFINED;
        lv = JS_GetPropertyStr(ctx, argv[2], "length");
        JS_ToUint32(ctx, &lu, lv);
        JS_FreeValue(ctx, lv);
        n = (int)lu > 32 ? 32 : (int)lu;
        for (i = 0; i < n; i++) {
            el = JS_GetPropertyUint32(ctx, argv[2], (uint32_t)i);
            regs[i] = parse_reg(ctx, el);
            JS_FreeValue(ctx, el);
        }
        for (i = n - 1; i >= 1; i -= 2)
            gum_arm64_writer_put_push_reg_reg(w, regs[i - 1], regs[i]);
        break;
    }
    case 13: {  /* putPopRegs */
        arm64_reg regs[32];
        int n = 0, i;
        uint32_t lu = 0;
        JSValue lv;
        if (!JS_IsArray(ctx, argv[2]))
            return JS_UNDEFINED;
        lv = JS_GetPropertyStr(ctx, argv[2], "length");
        JS_ToUint32(ctx, &lu, lv);
        JS_FreeValue(ctx, lv);
        n = (int)lu > 32 ? 32 : (int)lu;
        for (i = 0; i < n; i++) {
            el = JS_GetPropertyUint32(ctx, argv[2], (uint32_t)i);
            regs[i] = parse_reg(ctx, el);
            JS_FreeValue(ctx, el);
        }
        for (i = 0; i + 1 < n; i += 2)
            gum_arm64_writer_put_pop_reg_reg(w, regs[i], regs[i + 1]);
        break;
    }
    case 32: gum_arm64_writer_put_push_all_x_registers(w); break;
    case 33: gum_arm64_writer_put_pop_all_x_registers(w); break;
    case 14: {  /* putBytes(arrayBuffer) */
        size_t sz = 0;
        uint8_t *p = JS_GetArrayBuffer(ctx, &sz, argv[2]);
        if (p != NULL)
            gum_arm64_writer_put_bytes(w, p, (guint)sz);
        break;
    }
    case 15: gum_arm64_writer_put_branch_address(w, (GumAddress)(uintptr_t)a0); break;
    case 16: {  /* putCallAddressWithArgumentsArray(addr, args[]) */
        GumArgument args[16];
        int n = 0, i;
        uint32_t lu = 0;
        JSValue lv;
        if (argc < 4 || !JS_IsArray(ctx, argv[3]))
            return JS_UNDEFINED;
        lv = JS_GetPropertyStr(ctx, argv[3], "length");
        JS_ToUint32(ctx, &lu, lv);
        JS_FreeValue(ctx, lv);
        n = (int)lu > 16 ? 16 : (int)lu;
        for (i = 0; i < n; i++) {
            el = JS_GetPropertyUint32(ctx, argv[3], (uint32_t)i);
            if (JS_IsString(el)) {
                args[i].type = GUM_ARG_REGISTER;
                args[i].value.reg = (gint)parse_reg(ctx, el);
            } else {
                int64_t v = 0;
                JS_ToInt64(ctx, &v, el);
                args[i].type = GUM_ARG_ADDRESS;
                args[i].value.address = (GumAddress)(uintptr_t)v;
            }
            JS_FreeValue(ctx, el);
        }
        gum_arm64_writer_put_call_address_with_arguments_array(w,
            (GumAddress)(uintptr_t)a0, n, args);
        break;
    }
    case 17: gum_arm64_writer_put_cbnz_reg_label(w, (arm64_reg)a0, (gconstpointer)(uintptr_t)a1); break;
    case 18: gum_arm64_writer_put_cbz_reg_label(w, (arm64_reg)a0, (gconstpointer)(uintptr_t)a1); break;
    case 19: gum_arm64_writer_put_tbnz_reg_imm_label(w, (arm64_reg)a0,
                (uint8_t)a1, (gconstpointer)(uintptr_t)a2); break;
    case 20: gum_arm64_writer_put_tbz_reg_imm_label(w, (arm64_reg)a0,
                (uint8_t)a1, (gconstpointer)(uintptr_t)a2); break;
    case 21: gum_arm64_writer_put_add_reg_reg_imm(w, (arm64_reg)a0,
                (arm64_reg)a1, (gint64)a2); break;
    case 22: gum_arm64_writer_put_sub_reg_reg_imm(w, (arm64_reg)a0,
                (arm64_reg)a1, (gint64)a2); break;
    case 23: gum_arm64_writer_put_cmp_reg_reg(w, (arm64_reg)a0, (arm64_reg)a1); break;
    case 24: gum_arm64_writer_put_and_reg_reg_imm(w, (arm64_reg)a0, (arm64_reg)a1, (guint64)-1); break;
    case 25: gum_arm64_writer_put_mrs(w, (arm64_reg)a0, (guint32)a1); break;
    case 26: break;  /* put_msr unavailable in gum; unused on arm64 paths */
    case 27: gum_arm64_writer_put_bl_imm(w, (gint64)a0); break;
    case 28: gum_arm64_writer_flush(w); break;
    case 29: return JS_NewInt64(ctx, (int64_t)gum_arm64_writer_offset(w));
    case 30: gum_arm64_writer_put_b_label(w, (gconstpointer)(uintptr_t)a0); break;
    case 31: gum_arm64_writer_put_call_address_with_arguments_array; break; /* unused */
    case 99: gum_arm64_writer_clear(w); g_writer_used[h] = 0; break;
    default: break;
    }
    return JS_UNDEFINED;
}

void green_writer_register_natives(JSContext *ctx, JSValue global)
{
    JS_SetPropertyStr(ctx, global, "__green_a64w_new",
        JS_NewCFunction(ctx, js_a64w_new, "__green_a64w_new", 1));
    JS_SetPropertyStr(ctx, global, "__green_a64w",
        JS_NewCFunction(ctx, js_a64w, "__green_a64w", 3));
}
