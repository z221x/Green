// frida-style demo: hook com.goldrush.goldenretriever.goldenretriever_android
console.log("=== green hook demo ===");
console.log("process id:", Process.id, "| arch:", Process.arch);

// ---- 1. 模块枚举：找出 APP 自己的 native 库 ----
var mods = Process.enumerateModulesSync();
console.log("loaded modules:", mods.length);
var appLibs = [];
for (var i = 0; i < mods.length; i++) {
    if (mods[i].path.indexOf("/data/app/") === 0)
        appLibs.push(mods[i]);
}
console.log("app native libs:", appLibs.length);
for (var j = 0; j < appLibs.length && j < 5; j++)
    console.log("  lib:", appLibs[j].name, "0x" + appLibs[j].base.toString(16));

// ---- 2. NativeFunction：直接调用原生 getpid ----
var getpid = new NativeFunction(Module.getExportByName(null, "getpid"), "long", []);
console.log("NativeFunction getpid() =", getpid());

// ---- 3. Interceptor.attach：监控文件打开 ----
function tryAttach(name, cb) {
    try {
        Interceptor.attach(Module.getExportByName("libc.so", name), cb);
        console.log("hooked:", name);
        return true;
    } catch (e) {
        console.log("skip:", name, "-", String(e.message).slice(0, 40));
        return false;
    }
}

tryAttach("fopen", {
    onEnter: function (args) {
        var p = args[0].readUtf8String(120);
        if (p) console.log("fopen: " + p);
    }
});

tryAttach("opendir", {
    onEnter: function (args) {
        var p = args[0].readUtf8String(120);
        if (p) console.log("opendir: " + p);
    }
});

// ---- 4. Interceptor.replace：反反调试（ptrace 自检失效）----
Interceptor.replace(Module.getExportByName("libc.so", "ptrace"), function (args) {
    console.log("ptrace blocked, request=" + args[0].toInt32());
    return 0;
});
console.log("hooked: ptrace (anti-anti-debug)");

console.log("=== demo ready, streaming activity ===");
