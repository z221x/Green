/*
 * Broad Java/API regression probe for the green Java bridge.
 *
 * The probe deliberately uses framework classes so it can run in any app
 * process.  Each case is isolated: one failure is reported and the suite
 * continues, making partial API regressions visible in one attach session.
 */
(function () {
    function out(s) { log("[java-api] " + s); }
    function pass(name, value) {
        out("PASS " + name + (value === undefined ? "" : "=" + value));
    }
    function fail(name, e) {
        var msg = e && e.message ? e.message : String(e);
        out("FAIL " + name + "=" + msg);
    }
    function check(name, fn) {
        try {
            var value = fn();
            pass(name, value);
            return true;
        } catch (e) {
            fail(name, e);
            return false;
        }
    }
    function eq(name, actual, expected) {
        if (actual !== expected)
            throw new Error("expected " + expected + ", got " + actual);
        return actual;
    }

    out("START");
    try {
        if (!Java.available)
            throw new Error("Java.available is false");
        out("AVAILABLE");

        var run = function () {
            out("PERFORM_CB");
            var passed = 0, failed = 0;
            function runCase(name, fn) {
                if (check(name, fn)) passed++; else failed++;
            }

            var StringClass = Java.use("java.lang.String");
            var Integer = Java.use("java.lang.Integer");
            var Boolean = Java.use("java.lang.Boolean");
            var StringBuilder = Java.use("java.lang.StringBuilder");
            var ArrayList = Java.use("java.util.ArrayList");
            var System = Java.use("java.lang.System");
            out("USE_OK");

            // Construction, instance calls, equality and overload dispatch.
            runCase("string.new", function () {
                var s = StringClass.$new("green");
                return eq("string.new", s.toString(), "green");
            });
            runCase("string.instance", function () {
                var s = StringClass.$new("Green API");
                return eq("string.instance", s.toUpperCase(), "GREEN API");
            });
            runCase("string.overload", function () {
                var s = StringClass.$new("abcdef");
                return eq("string.overload", s.substring.overload("int", "int").call(s, 1, 4), "bcd");
            });
            runCase("string.equals", function () {
                var a = StringClass.$new("same");
                var b = StringClass.$new("same");
                return eq("string.equals", a.equals(b), true);
            });

            // Primitive wrappers and static methods/fields.
            runCase("integer.new", function () {
                var n = Integer.$new(42);
                return eq("integer.new", n.intValue(), 42);
            });
            runCase("integer.static", function () {
                return eq("integer.static", Integer.parseInt.overload("java.lang.String").call(Integer, "1234"), 1234);
            });
            runCase("integer.field", function () {
                return eq("integer.field", Integer.MAX_VALUE.value, 2147483647);
            });
            runCase("boolean.static", function () {
                return eq("boolean.static", Boolean.parseBoolean.overload("java.lang.String").call(Boolean, "true"), true);
            });

            // Java arrays and collection object chaining.
            runCase("array.string", function () {
                var a = Java.array("java.lang.String", ["a", "b", "c"]);
                return eq("array.string", a.length, 3);
            });
            runCase("array.int", function () {
                var a = Java.array("int", [4, 5, 6]);
                return eq("array.int", a.length, 3);
            });
            runCase("array.collection", function () {
                var list = ArrayList.$new();
                list.add("first");
                list.add("second");
                return eq("array.collection", list.get(1).toString(), "second");
            });
            runCase("collection.size", function () {
                var list = ArrayList.$new();
                list.add("x");
                list.add("y");
                return eq("collection.size", list.size(), 2);
            });

            // Hook a second framework method and call the original from the
            // implementation. This exercises replacement, re-entry and the
            // return-value path on a non-hashCode method.
            runCase("hook.stringbuilder", function () {
                var toString = StringBuilder.toString.overload();
                var depth = 0;
                var body = 0;
                toString.implementation = function () {
                    body++;
                    if (depth !== 0) return "<recursion>";
                    depth++;
                    var original = this.toString();
                    depth--;
                    return original + "|hook";
                };
                var b = StringBuilder.$new();
                b.append.overload("java.lang.String").call(b, "api");
                var result = b.toString();
                if (body < 1) throw new Error("hook body did not run");
                return eq("hook.stringbuilder", result, "api|hook");
            });

            // Static platform API and a harmless exception path.
            runCase("system.static", function () {
                var t = System.currentTimeMillis();
                if (typeof t !== "number" && typeof t !== "object")
                    throw new Error("unexpected return type " + typeof t);
                return "ok";
            });
            runCase("exception.path", function () {
                try {
                    Integer.parseInt.overload("java.lang.String").call(Integer, "not-an-int");
                    throw new Error("parseInt unexpectedly succeeded");
                } catch (e) {
                    return "caught";
                }
            });

            // Runtime metadata and process-side native bridge sanity checks.
            runCase("java.enumerate", function () {
                var classes = Java.enumerateLoadedClassesSync();
                if (!classes || classes.length === 0) throw new Error("no loaded classes");
                return classes.length;
            });
            runCase("process.metadata", function () {
                if (Process.id <= 0 || Process.arch !== "arm64")
                    throw new Error("unexpected process metadata");
                return Process.id;
            });
            runCase("native.getpid", function () {
                var getpid = new NativeFunction(Module.getExportByName(null, "getpid"), "long", []);
                var pid = getpid();
                return eq("native.getpid", pid.toNumber(), Process.id);
            });

            out("SUMMARY passed=" + passed + " failed=" + failed);
        };
        if (typeof Java.performNow === "function")
            Java.performNow(run);
        else
            Java.perform(run);
    } catch (e) {
        var detail = e && e.stack ? e.stack : String(e);
        out("FATAL=" + String(e));
        out("FATAL_STACK=" + detail);
    }
})();
