/* Native/Memory API probe.  Keep the target process alive and exercise only
 * private allocations and getpid/strlen, so the probe does not alter app
 * behavior beyond one short-lived libc hook. */
(function () {
    function out(s) { console.log("[native-api] " + s); }
    function pass(name, value) { out("PASS " + name + (value === undefined ? "" : "=" + value)); }
    function fail(name, e) { out("FAIL " + name + "=" + (e && e.message ? e.message : String(e))); }
    function check(name, fn) {
        try { pass(name, fn()); return true; }
        catch (e) { fail(name, e); return false; }
    }
    function eq(name, actual, expected) {
        if (actual !== expected) throw new Error(name + " expected " + expected + ", got " + actual);
        return actual;
    }

    var passed = 0, failed = 0;
    function run(name, fn) { if (check(name, fn)) passed++; else failed++; }

    out("START");
    run("process", function () {
        if (Process.id <= 0 || Process.arch !== "arm64") throw new Error("bad process metadata");
        return Process.id;
    });
    run("modules", function () {
        var ms = Process.enumerateModulesSync();
        if (!ms || ms.length < 3) throw new Error("too few modules");
        return ms.length;
    });
    run("memory.primitives", function () {
        var p = Memory.alloc(32);
        p.writeU8(0xab, 0);
        p.writeS32(-123456, 4);
        p.writeU64(0x1234567890n, 8);
        return eq("u8", p.readU8(), 0xab) &&
            eq("s32", p.readS32(4), -123456) &&
            eq("u64", p.readU64(8).toString(16), "1234567890");
    });
    run("memory.strings", function () {
        var u8 = Memory.allocUtf8String("green-native");
        var u16 = Memory.allocUtf16String("绿");
        return eq("utf8", u8.readUtf8String(), "green-native") &&
            eq("utf16", u16.readUtf16String(), "绿");
    });
    run("memory.pointer", function () {
        var text = Memory.allocUtf8String("pointer-ok");
        var slot = Memory.alloc(8);
        slot.writePointer(text);
        return eq("pointer", slot.readPointer().readUtf8String(), "pointer-ok");
    });
    run("memory.copy.scan", function () {
        var src = Memory.allocUtf8String("scan-ok");
        var dst = Memory.alloc(16);
        Memory.copy(dst, src, 8);
        var hits = Memory.scanSync(dst, 8, "73 63 61 6e");
        if (!hits || hits.length !== 1) throw new Error("scan match count=" + (hits && hits.length));
        return dst.readUtf8String(8);
    });
    run("native.getpid", function () {
        var f = new NativeFunction(Module.getExportByName(null, "getpid"), "int", []);
        return eq("getpid", f(), Process.id);
    });
    run("native.strlen", function () {
        var f = new NativeFunction(Module.getExportByName(null, "strlen"), "ulong", ["pointer"]);
        var s = Memory.allocUtf8String("1234567");
        return eq("strlen", f(s).toNumber(), 7);
    });
    run("interceptor.attach", function () {
        /* getpid has no arguments; use libc's strlen for the one-argument
         * callback shape exercised below. */
        var target = Module.getExportByName(null, "strlen");
        var f = new NativeFunction(target, "ulong", ["pointer"]);
        var input = Memory.allocUtf8String("green");
        eq("baseline", f(input).toNumber(), 5);
        var enters = 0, leaves = 0;
        Interceptor.attach(target, {
            onEnter: function (args) {
                if (args[0].readUtf8String() === "green") enters++;
            },
            onLeave: function (retval) { if (retval.toInt32() === 5) leaves++; }
        });
        var n = f(input);
        if (n.toNumber() !== 5 || enters !== 1 || leaves !== 1)
            throw new Error("n=" + n + " enters=" + enters + " leaves=" + leaves);
        return "ok";
    });
    out("SUMMARY passed=" + passed + " failed=" + failed);
})();
