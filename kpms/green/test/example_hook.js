log("green js: script loaded");

const target = selfTestTarget();
log("green js: hooking " + target);

hook(target, function (args) {
    log("green js: hooked! arg0=" + args[0]);
    return args[0] + 100;
});
