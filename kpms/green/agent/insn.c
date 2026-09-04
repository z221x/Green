/* frida-style Instruction.parse() over capstone — minimal subset for
 * frida-java-bridge's instruction offset detection. */

#include <string.h>
#include <capstone.h>
#include <android/log.h>
#include <arm64.h>
#include <quickjs.h>
#include <linux/errno.h>
extern void green_maps_refresh(void);
extern int green_maps_addr_readable(uint64_t addr, size_t len);
extern int green_addr_ok(uint64_t addr, size_t len, int need);

static csh g_cs;
static int g_cs_ready;

static JSValue js_insn_parse(JSContext *ctx, JSValueConst this_val,
                             int argc, JSValueConst *argv)
{
    uint64_t address = 0;
    cs_insn *insn = NULL;
    cs_arm64 *detail;
    JSValue o, ops;
    int i, count;
    size_t sz = 4;
    uint64_t pc = 0;

    (void)this_val;
    if (!g_cs_ready) {
        /* Mirror gum's own init: CS_MODE_ARM|CS_MODE_V8|LITTLE_ENDIAN */
        cs_mode mode = (cs_mode)CS_MODE_LITTLE_ENDIAN;  /* v6: plain LE */
        if (cs_open(CS_ARCH_ARM64, mode, &g_cs) != CS_ERR_OK)
            return JS_NULL;
        cs_option(g_cs, CS_OPT_DETAIL, CS_OPT_ON);
        g_cs_ready = 1;
    }
    if (argc < 1)
        return JS_NULL;
    {
        /* Accept NativePointer instances (unbox __v), BigInt or numbers. */
        JSValue v = argv[0];
        if (JS_IsObject(v)) {
            JSValue iv = JS_GetPropertyStr(ctx, v, "__v");
            if (JS_IsUndefined(iv)) {
                /* NativeFunction / other wrapped objects expose .address */
                JS_FreeValue(ctx, iv);
                iv = JS_GetPropertyStr(ctx, v, "address");
                if (JS_IsUndefined(iv) || JS_IsException(iv)) {
                    JS_FreeValue(ctx, iv);
                    return JS_NULL;
                }
                if (JS_IsObject(iv)) {
                    JSValue av = JS_GetPropertyStr(ctx, iv, "__v");
                    JS_FreeValue(ctx, iv);
                    iv = av;
                }
            }
            if (JS_IsUndefined(iv) || JS_IsException(iv)) {
                JS_FreeValue(ctx, iv);
                return JS_NULL;
            }
            if (JS_IsBigInt(ctx, iv))
                JS_ToBigInt64(ctx, (int64_t *)&address, iv);
            else
                JS_ToInt64(ctx, (int64_t *)&address, iv);
            JS_FreeValue(ctx, iv);
        } else {
            if (JS_IsBigInt(ctx, v))
                JS_ToBigInt64(ctx, (int64_t *)&address, v);
            else if (JS_ToInt64(ctx, (int64_t *)&address, v) != 0)
                return JS_NULL;
        }
    }
    pc = address;
    {
        static int oklog = 0;
        if (oklog < 5) {
            __android_log_print(ANDROID_LOG_ERROR, "green-agent",
                "insn_parse: addr=%llx", (unsigned long long)address);
            oklog++;
        }
    }
    if (!green_maps_addr_readable(address, 4)) {
        /* Unreadable: neutral pseudo-instruction */
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "mnemonic", JS_NewString(ctx, "bad"));
        JS_SetPropertyStr(ctx, o, "op_str", JS_NewString(ctx, ""));
        JS_SetPropertyStr(ctx, o, "operands", JS_NewArray(ctx));
        JS_SetPropertyStr(ctx, o, "address",
            JS_NewInt64(ctx, (int64_t)address));
        JS_SetPropertyStr(ctx, o, "next",
            JS_NewInt64(ctx, (int64_t)(address + 4)));
        JS_SetPropertyStr(ctx, o, "size", JS_NewInt32(ctx, 4));
        return o;
    }
    {
        static int logged = 0;
        if (logged < 20) {
            __android_log_print(ANDROID_LOG_ERROR, "green-agent",
                "insn_parse: addr=%llx", (unsigned long long)address);
            logged++;
        }
    }

    if ((insn = cs_malloc(g_cs)) == NULL)
        return JS_NULL;
    if (!cs_disasm_iter(g_cs, (const uint8_t **)&address, &sz, &pc, insn)) {
        /* Unparseable (data/padding): frida would throw, but frida-java-
         * bridge's offset scanners just skip patterns — return a neutral
         * pseudo-instruction so the scan can continue. */
        cs_free(insn, 1);
        JSValue o = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, o, "mnemonic", JS_NewString(ctx, "bad"));
        JS_SetPropertyStr(ctx, o, "op_str", JS_NewString(ctx, ""));
        JS_SetPropertyStr(ctx, o, "operands", JS_NewArray(ctx));
        JS_SetPropertyStr(ctx, o, "address", JS_NewInt64(ctx, (int64_t)pc));
        JS_SetPropertyStr(ctx, o, "next",
            JS_NewInt64(ctx, (int64_t)(pc + 4)));
        JS_SetPropertyStr(ctx, o, "size", JS_NewInt32(ctx, 4));
        return o;
    }

    o = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, o, "address",
        JS_NewInt64(ctx, (int64_t)insn->address));
    JS_SetPropertyStr(ctx, o, "size", JS_NewInt32(ctx, (int)insn->size));
    JS_SetPropertyStr(ctx, o, "mnemonic", JS_NewString(ctx, insn->mnemonic));
    JS_SetPropertyStr(ctx, o, "op_str", JS_NewString(ctx, insn->op_str));
    JS_SetPropertyStr(ctx, o, "next",
        JS_NewInt64(ctx, (int64_t)(insn->address + insn->size)));

    detail = &insn->detail->arm64;
    ops = JS_NewArray(ctx);
    count = detail->op_count;
    if (count > 8)
        count = 8;
    for (i = 0; i < count; i++) {
        JSValue op = JS_NewObject(ctx);
        cs_arm64_op *opd = &detail->operands[i];
        switch (opd->type) {
        case ARM64_OP_REG: {
            const char *rn = cs_reg_name(g_cs, opd->reg);
            JS_SetPropertyStr(ctx, op, "type", JS_NewString(ctx, "reg"));
            JS_SetPropertyStr(ctx, op, "value",
                JS_NewString(ctx, rn ? rn : "?"));
            break;
        }
        case ARM64_OP_IMM:
            JS_SetPropertyStr(ctx, op, "type", JS_NewString(ctx, "imm"));
            JS_SetPropertyStr(ctx, op, "value",
                JS_NewInt64(ctx, (int64_t)opd->imm));
            break;
        case ARM64_OP_MEM: {
            JSValue mv = JS_NewObject(ctx);
            const char *bn = cs_reg_name(g_cs, opd->mem.base);
            const char *in = cs_reg_name(g_cs, opd->mem.index);
            JS_SetPropertyStr(ctx, op, "type", JS_NewString(ctx, "mem"));
            JS_SetPropertyStr(ctx, mv, "base",
                JS_NewString(ctx, bn ? bn : ""));
            JS_SetPropertyStr(ctx, mv, "index",
                JS_NewString(ctx, in ? in : ""));
            JS_SetPropertyStr(ctx, mv, "scale", JS_NewInt32(ctx, 1));
            JS_SetPropertyStr(ctx, mv, "disp",
                JS_NewInt64(ctx, opd->mem.disp));
            JS_SetPropertyStr(ctx, op, "value", mv);
            break;
        }
        default:
            JS_SetPropertyStr(ctx, op, "type", JS_NewString(ctx, "imm"));
            JS_SetPropertyStr(ctx, op, "value", JS_NewInt32(ctx, 0));
            break;
        }
        JS_SetPropertyUint32(ctx, ops, (uint32_t)i, op);
    }
    JS_SetPropertyStr(ctx, o, "operands", ops);
    cs_free(insn, 1);
    return o;
}

static JSValue js_insn_selftest(JSContext *ctx, JSValueConst this_val,
                                int argc, JSValueConst *argv)
{
    csh h = 0;
    cs_err e;
    cs_insn *insn = NULL;
    size_t sz = 4;
    const uint8_t code[4] = { 0x00, 0x00, 0x80, 0xd2 };  /* mov x0, #0 */

    (void)this_val; (void)argc; (void)argv;
    e = cs_open(CS_ARCH_ARM64, (cs_mode)CS_MODE_LITTLE_ENDIAN, &h);
    __android_log_print(ANDROID_LOG_ERROR, "green-agent",
        "selftest: open=%d h=%p", (int)e, (void *)(uintptr_t)h);
    if (e != CS_ERR_OK)
        return JS_NewInt32(ctx, (int)e);
    e = cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    __android_log_print(ANDROID_LOG_ERROR, "green-agent",
        "selftest: option=%d", (int)e);
    if ((insn = cs_malloc(h)) == NULL)
        return JS_NewInt32(ctx, -1);
    {
        const uint8_t *codep = code;
        uint64_t addr = 0;
        int ok = cs_disasm_iter(h, &codep, &sz, &addr, insn);
        __android_log_print(ANDROID_LOG_ERROR, "green-agent",
            "selftest: disasm=%d mnem=%s", (int)ok, ok ? insn->mnemonic : "-");
    }
    cs_free(insn, 1);
    cs_close(&h);
    return JS_NewInt32(ctx, 0);
}

void green_insn_register_natives(JSContext *ctx, JSValue global)
{
    JS_SetPropertyStr(ctx, global, "__green_insn_selftest",
        JS_NewCFunction(ctx, js_insn_selftest, "__green_insn_selftest", 0));
    {
    JSValue ctor = JS_NewCFunction(ctx, js_insn_parse, "parse", 1);
    JSValue insn_obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, insn_obj, "parse", ctor);
    JS_SetPropertyStr(ctx, global, "Instruction", insn_obj);
    }
}

