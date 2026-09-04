/*
 * Java hook probe for the green payload.
 *
 * Expected result for java.lang.String("123"):
 *   PROBE_BEFORE=48690
 *   PROBE_HOOK_SET
 *   PROBE_BODY
 *   PROBE_ORIGINAL=48690
 *   PROBE_AFTER=48690
 *
 * A PROBE_ORIGINAL/PROBE_AFTER value of 0 means the hook entered but the
 * original-method path is still broken.  The recursion guard makes the
 * result deterministic if calling this.hashCode() re-enters the hook.
 */
(function () {
    function out(s) { log("[java-probe] " + s); }

    out("START");
    try {
        if (!Java.available)
            throw new Error("Java.available is false");

        out("AVAILABLE");
        var run = function () {
            out("PERFORM_CB");

            var StringClass = Java.use("java.lang.String");
            out("USE_OK");

            var hashCode = StringClass.hashCode.overload();
            out("OVERLOAD_OK");

            var value = StringClass.$new("123");
            var before = value.hashCode();
            out("PROBE_BEFORE=" + before);

            var depth = 0;
            hashCode.implementation = function () {
                out("PROBE_BODY");
                if (depth !== 0) {
                    out("PROBE_RECURSION");
                    return 0;
                }
                depth++;
                var original = this.hashCode();
                depth--;
                out("PROBE_ORIGINAL=" + original);
                return original;
            };
            out("PROBE_HOOK_SET");
            out("PROBE_AFTER=" + value.hashCode());
        };
        if (typeof Java.performNow === "function")
            Java.performNow(run);
        else
            Java.perform(run);
    } catch (e) {
        var detail = e && e.stack ? e.stack : String(e);
        out("PROBE_ERROR=" + String(e));
        out("PROBE_ERROR_STACK=" + detail);
    }
})();
