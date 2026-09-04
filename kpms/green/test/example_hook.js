/* Minimal standard Frida GumJS example.  It intentionally uses only public
 * Process/Module/Interceptor APIs; Green does not provide a custom `hook()`
 * helper anymore. */
console.log("green js: script loaded, pid=" + Process.id);

const target = Module.getExportByName(null, "getpid");
Interceptor.attach(target, {
    onEnter() {
        console.log("green js: getpid entered");
    },
    onLeave(retval) {
        console.log("green js: getpid returned " + retval.toInt32());
    }
});
