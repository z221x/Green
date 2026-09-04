/* Standard Frida code-page probe.
 *
 * The generated function lives in a private anonymous page, so this test does
 * not change an application/library mapping. Memory.patchCode must still use
 * Green's authenticated KPM shadow backend because the page is made
 * executable before the patch is committed.
 */
(function () {
    function out(s) { console.log("[shadow-api] " + s); }

    out("START");
    try {
        if (Process.arch !== "arm64")
            throw new Error("this probe requires arm64");

        var page = Memory.alloc(Process.pageSize);
        if (!Memory.protect(page, Process.pageSize, "rwx"))
            throw new Error("Memory.protect failed");

        Memory.patchCode(page, 8, function (code) {
            /* mov w0, #123; ret */
            code.writeU32(0x52800f60);
            code.add(4).writeU32(0xd65f03c0);
        });

        var fn = new NativeFunction(page, "int", []);
        var result = fn();
        if (result !== 123)
            throw new Error("patched function returned " + result);
        out("PASS Memory.patchCode result=" + result);
    } catch (e) {
        out("FAIL " + (e && e.stack ? e.stack : String(e)));
    }
})();
