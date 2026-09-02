var Process = {
    id: __green_pid(),
    arch: 'arm64',
    platform: 'linux',
    pageSize: 4096,
    enumerateModulesSync: __green_modules
};
Process.enumerateModules = function () { return __green_modules(); };
Process.findModuleByName = function (name) {
    var ms = __green_modules();
    for (var i = 0; i < ms.length; i++) if (ms[i].name === name) return ms[i];
    return null;
};
Process.getModuleByName = function (name) {
    var m = Process.findModuleByName(name);
    if (m === null) throw new Error('module not found: ' + name);
    return m;
};
Process.findModuleByAddress = function (addr) {
    var a = Number(new NativePointer(addr).__v);
    var ms = __green_modules();
    for (var i = 0; i < ms.length; i++)
        if (a >= ms[i].base && a < ms[i].base + ms[i].size) return ms[i];
    return null;
};
var Module = {
    enumerateModulesSync: __green_modules,
    enumerateModules: function () { return __green_modules(); },
    getBaseAddress: function (name) {
        var ms = __green_modules();
        for (var i = 0; i < ms.length; i++)
            if (ms[i].name === name || ms[i].path === name)
                return ms[i].base;
        throw new Error('Module not found: ' + name);
    },
    findBaseAddress: function (name) {
        try { return Module.getBaseAddress(name); }
        catch (e) { return null; }
    },
    findExportByName: function (moduleName, exportName) {
        if (moduleName === null)
            return __green_dlsym(0, exportName) === null ? null
                : new NativePointer(__green_dlsym(0, exportName));
        var handle = __green_dlopen((function (m) {
            var ms = __green_modules();
            for (var i = 0; i < ms.length; i++)
                if (ms[i].name === moduleName || ms[i].path === moduleName)
                    return ms[i].path;
            return moduleName;
          })(moduleName));
        if (handle === null) return null;
        var a = __green_dlsym(handle, exportName);
        return a === null ? null : new NativePointer(a);
    },
    getExportByName: function (moduleName, exportName) {
        var a = Module.findExportByName(moduleName, exportName);
        if (a === null) throw new Error('export not found: ' + exportName);
        return a;
    },
    load: function (path) { return new NativePointer(__green_dlopen(path)); }
};
var console = {
    log: function () { log(Array.prototype.join.call(arguments, ' ')); },
    info: function () { log(Array.prototype.join.call(arguments, ' ')); },
    warn: function () { log(Array.prototype.join.call(arguments, ' ')); },
    error: function () { log(Array.prototype.join.call(arguments, ' ')); }
};

function __green_to_ptr(v) {
    if (v instanceof NativePointer) return v;
    return new NativePointer(v);
}
class NativePointer {
    constructor(v) {
        if (v instanceof NativePointer) { this.__v = v.__v; return; }
        if (v === null || v === undefined) { this.__v = 0n; return; }
        if (typeof v === 'bigint') { this.__v = BigInt.asUintN(64, v); return; }
        if (typeof v === 'number') { this.__v = BigInt.asUintN(64, BigInt(Math.trunc(v))); return; }
        if (typeof v === 'string') {
            var t = v.trim().toLowerCase();
            if (!t.startsWith('0x') && /^-?[0-9a-f]+$/.test(t)) t = '0x' + t;
            this.__v = BigInt.asUintN(64, BigInt(t));
            return;
        }
        this.__v = BigInt.asUintN(64, BigInt(v));
    }
    add(o) { return new NativePointer(this.__v + __green_to_ptr(o).__v); }
    sub(o) { return new NativePointer(this.__v - __green_to_ptr(o).__v); }
    and(o) { return new NativePointer(this.__v & __green_to_ptr(o).__v); }
    or(o) { return new NativePointer(this.__v | __green_to_ptr(o).__v); }
    xor(o) { return new NativePointer(this.__v ^ __green_to_ptr(o).__v); }
    shr(o) { return new NativePointer(this.__v >> BigInt(o)); }
    shl(o) { return new NativePointer(this.__v << BigInt(o)); }
    not() { return new NativePointer(~this.__v); }
    isNull() { return this.__v === 0n; }
    equals(o) { return this.__v === __green_to_ptr(o).__v; }
    compare(o) {
        var a = this.__v, b = __green_to_ptr(o).__v;
        return a < b ? -1 : (a > b ? 1 : 0);
    }
    toInt32() { return Number(BigInt.asIntN(32, this.__v)); }
    toString(radix) {
        radix = radix || 16;
        return radix === 16 ? '0x' + this.__v.toString(16) : this.__v.toString(radix);
    }
    toJSON() { return this.toString(); }
    readByteArray(len) {
        var b = __green_mem_read(Number(this.__v), len);
        if (b === null) throw new Error('access violation reading ' + len + ' bytes');
        return b;
    }
    writeByteArray(buf) {
        if (!__green_mem_write(Number(this.__v), buf))
            throw new Error('access violation writing ' + buf.byteLength + ' bytes');
    }
    readUtf8String(len) {
        var s = __green_read_utf8(Number(this.__v), len || 512);
        if (s === null) throw new Error('access violation reading string');
        var z = s.indexOf('\u0000');
        return z >= 0 ? s.slice(0, z) : s;
    }
    readCString(len) { return this.readUtf8String(len); }
}
(function () {
    var rw = {
        readS8: [1, 'getInt8'], readU8: [1, 'getUint8'],
        readS16: [2, 'getInt16'], readU16: [2, 'getUint16'],
        readS32: [4, 'getInt32'], readU32: [4, 'getUint32'],
        readS64: [8, 'getBigInt64'], readU64: [8, 'getBigUint64'],
        readFloat: [4, 'getFloat32'], readDouble: [8, 'getFloat64']
    };
    for (var name in rw) {
        (function (name, size, getter) {
            NativePointer.prototype[name] = function (offset) {
                var a = Number(this.__v) + (offset || 0);
                var b = __green_mem_read(a, size);
                if (b === null) throw new Error('access violation reading ' + size + ' byte(s) at 0x' + a.toString(16));
                var dv = new DataView(b);
                return dv[getter](0, true);
            };
            var wname = 'write' + name.slice(4);
            NativePointer.prototype[wname] = function (value, offset) {
                var a = Number(this.__v) + (offset || 0);
                var b = new ArrayBuffer(size);
                var dv = new DataView(b);
                var setter = getter.replace('get', 'set');
                if (getter === 'getFloat32' || getter === 'getFloat64')
                    dv[setter](0, Number(value), true);
                else if (size === 8)
                    dv[setter](0, typeof value === 'bigint' ? value : BigInt(value), true);
                else
                    dv[setter](0, value, true);
                if (!__green_mem_write(a, b))
                    throw new Error('access violation writing at 0x' + a.toString(16));
                return this;
            };
        })(name, rw[name][0], rw[name][1]);
    }
})();
NativePointer.prototype.readPointer = function () {
    return new NativePointer(this.readU64());
};
NativePointer.prototype.writePointer = function (v) {
    this.writeU64(new NativePointer(v).__v);
    return this;
};
function ptr(v) { return new NativePointer(v); }
NativePointer.prototype.toMatchPattern = function () {
    var v = BigInt.asUintN(64, BigInt(this.__v));
    var s = [];
    for (var i = 0; i < 8; i++) {
        var b = Number((v >> BigInt(8 * i)) & 0xffn);
        s.push((b < 16 ? '0' : '') + b.toString(16));
    }
    return s.join(' ').toUpperCase();
};
NativePointer.prototype.toUInt32 = function () { return Number(BigInt.asUintN(32, BigInt(this.__v))); };
function hexdump(addr, options) {
    var o = options || {};
    var p = new NativePointer(addr);
    var len = o.length || 256;
    var off = o.offset || 0;
    var base = o.base !== undefined ? Number(new NativePointer(o.base).__v) : Number(p.__v);
    var lines = [];
    for (var i = 0; i < len; i += 16) {
        var a = Number(p.__v) + off + i;
        var bytes = new NativePointer(a).readByteArray(Math.min(16, len - i));
        var hex = '', asc = '';
        for (var j = 0; j < bytes.length; j++) {
            var b = bytes[j];
            hex += (b < 16 ? '0' : '') + b.toString(16) + ' ';
            asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
        }
        while (hex.length < 48) hex += ' ';
        lines.push('0x' + (base + i).toString(16).padStart(12, '0') + '  ' + hex + ' ' + asc);
    }
    var out = lines.join('\n');
    log(out);
    return out;
}
class Int64 {
    constructor(v) {
        if (v instanceof Int64) { this.__v = v.__v; return; }
        this.__v = BigInt.asIntN(64, typeof v === 'bigint' ? v : BigInt(v));
    }
    add(o) { return new Int64(this.__v + new Int64(o).__v); }
    sub(o) { return new Int64(this.__v - new Int64(o).__v); }
    and(o) { return new Int64(this.__v & new Int64(o).__v); }
    or(o) { return new Int64(this.__v | new Int64(o).__v); }
    xor(o) { return new Int64(this.__v ^ new Int64(o).__v); }
    shr(o) { return new Int64(this.__v >> BigInt(o)); }
    shl(o) { return new Int64(this.__v << BigInt(o)); }
    not() { return new Int64(~this.__v); }
    compare(o) {
        var a = this.__v, b = new Int64(o).__v;
        return a < b ? -1 : (a > b ? 1 : 0);
    }
    toNumber() { return Number(this.__v); }
    toString(radix) { return this.__v.toString(radix || 10); }
    toJSON() { return this.toString(); }
    valueOf() { return this.toNumber(); }
}
class UInt64 {
    constructor(v) {
        if (v instanceof UInt64) { this.__v = v.__v; return; }
        this.__v = BigInt.asUintN(64, typeof v === 'bigint' ? v : BigInt(v));
    }
    add(o) { return new UInt64(this.__v + new UInt64(o).__v); }
    sub(o) { return new UInt64(this.__v - new UInt64(o).__v); }
    and(o) { return new UInt64(this.__v & new UInt64(o).__v); }
    or(o) { return new UInt64(this.__v | new UInt64(o).__v); }
    xor(o) { return new UInt64(this.__v ^ new UInt64(o).__v); }
    shr(o) { return new UInt64(this.__v >> BigInt(o)); }
    shl(o) { return new UInt64(this.__v << BigInt(o)); }
    not() { return new UInt64(~this.__v); }
    compare(o) {
        var a = this.__v, b = new UInt64(o).__v;
        return a < b ? -1 : (a > b ? 1 : 0);
    }
    toNumber() { return Number(this.__v); }
    toString(radix) { return this.__v.toString(radix || 10); }
    toJSON() { return this.toString(); }
    valueOf() { return this.toNumber(); }
}
function __green_to_big(v) {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number') return BigInt(Math.trunc(v));
    if (v && v.__v !== undefined) return v.__v;
    return BigInt(v);
}
function __green_wrap_ret(raw, type) {
    raw = __green_to_big(raw);
    switch (type) {
        case 'pointer': return new NativePointer(raw);
        case 'int': return Number(BigInt.asIntN(32, raw));
        case 'uint': return Number(BigInt.asUintN(32, raw));
        case 'long': case 'int64': return new Int64(raw);
        case 'ulong': case 'uint64': return new UInt64(raw);
        case 'char': return Number(BigInt.asIntN(8, raw));
        case 'size_t': return new UInt64(raw);
        default: return Number(BigInt.asIntN(32, raw));
    }
}
function __green_wrap_args(raw, type) {
    raw = __green_to_big(raw);
    switch (type) {
        case 'pointer': return new NativePointer(raw);
        case 'uint': return Number(BigInt.asUintN(32, raw));
        case 'int64': return new Int64(raw);
        case 'uint64': return new UInt64(raw);
        default: return Number(BigInt.asIntN(32, raw));
    }
}
function NativeFunction(addr, retType, argTypes) {
    var target = Number(new NativePointer(addr).__v);
    var f = function () {
        var args = [];
        for (var i = 0; i < argTypes.length; i++) {
            var a = arguments[i];
            args.push(a instanceof NativePointer ? Number(a.__v)
                : (a === undefined || a === null ? 0 : a));
        }
        return __green_wrap_ret(__green_native_call(target, args), retType);
    };
    f.address = new NativePointer(addr);
    f.retType = retType;
    f.argTypes = argTypes;
    return f;
}
function NativeCallback(fn, retType, argTypes) {
    return new NativePointer(__green_new_callback(function (args) {
        var a = [];
        for (var i = 0; i < argTypes.length; i++)
            a.push(__green_wrap_args(args[i], argTypes[i]));
        var r = fn.apply(null, a);
        return r === undefined ? 0 : r;
    }));
}
var Interceptor = {
    replace: function (target, replacement) { hook(target, replacement); },
    revert: function (target) { unhook(target); },
    flush: function () {},
    attach: function (target, callbacks) {
        var t = Number(new NativePointer(target).__v);
        return __green_interceptor_attach(t,
            callbacks && callbacks.onEnter
                ? function (args) { callbacks.onEnter(args.map(function (a) { return new NativePointer(a); })); } : undefined,
            callbacks && callbacks.onLeave
                ? function (retval_raw) {
                    var retval = {
                        _v: retval_raw,
                        toInt32: function () { return Number(BigInt.asIntN(32, BigInt(this._v))); },
                        replace: function (v) { this._v = (typeof v === 'object' && v !== null && v.__v !== undefined) ? Number(v.__v) : v; }
                    };
                    callbacks.onLeave(retval);
                    return retval._v;
                } : undefined);
    }
};
var Memory = {
    alloc: function (size) { return new NativePointer(__green_mem_alloc(size || 4096)); },
    free: function (p) { __green_mem_free(Number(new NativePointer(p).__v)); },
    protect: function (p, size, prot) {
        return __green_mprotect(Number(new NativePointer(p).__v), size, prot);
    },
    readUtf8String: function (addr, len) { return new NativePointer(addr).readUtf8String(len); },
    readCString: function (addr, len) { return new NativePointer(addr).readUtf8String(len); },
    readByteArray: function (addr, len) { return new NativePointer(addr).readByteArray(len); },
    writeByteArray: function (addr, bytes) { new NativePointer(addr).writeByteArray(bytes); }
};
Process.getCurrentThreadId = __green_gettid;
Process.sleep = function (ms) { __green_sleep(ms); };
Process.isDebuggerAttached = function () { return false; };
var Thread = { sleep: function (ms) { __green_sleep(ms); } };
var File = {
    readAll: function (path) { return __green_read_file(path); },
    writeAll: function (path, data) { return __green_file_write(path, data); }
};
function send(message) {
    __green_send(typeof message === 'string' ? message : JSON.stringify(message));
}

/* ---- recv() / rpc.exports ------------------------------------------ */
var __green_recv_cbs = {};
var __green_recv_queue = {};
function recv(type, callback) {
    __green_recv_cbs[type] = callback;
    if (__green_recv_queue[type] !== undefined) {
        var p = __green_recv_queue[type];
        delete __green_recv_queue[type];
        callback({ type: type, payload: JSON.parse(p) });
    }
}
function __green_recv_dispatch(type, payload_json) {
    __green_recv_queue[type] = payload_json;
    var cb = __green_recv_cbs[type];
    if (cb) {
        var p = __green_recv_queue[type];
        delete __green_recv_queue[type];
        cb({ type: type, payload: JSON.parse(p) });
    }
}
var rpc = { exports: {} };

/* ---- Java bridge ---------------------------------------------------- */
var Java = { available: false, __classes: {}, __classIds: {} };

Java.perform = function (fn) {
    if (!Java.available) throw new Error('Java VM not available');
    fn();
};
Java.use = function (name) {
    if (!Java.available) throw new Error('Java VM not available');
    if (Java.__classes[name]) return Java.__classes[name];
    var clsId = __green_java_find_class(name);
    if (clsId === null || clsId === 0) throw new Error('Class not found: ' + name);
    Java.__classIds[name] = clsId;
    var info = __green_java_class_info(clsId);
    var w = Java.__classes[name] = __gj_wrap_class(name, clsId, info);
    return w;
};
Java.cast = function (obj, klass) {
    if (typeof obj === 'string') return obj;
    return __gj_wrap_instance(klass.__name, obj);
};
Java.scheduleOnMainThread = function (fn) { fn(); };  /* simplification */

function __gj_meth(mid, name, sig, isStatic, clsName) {
    /* One overload.  m(...) invokes it; .implementation replaces it. */
    var m = function () {
        return __gj_call(clsName, 0, mid, sig, isStatic, arguments);
    };
    m.__mid = mid; m.__sig = sig; m.__static = isStatic;
    m.__name = name; m.__cls = clsName;
    m.overload = function () { return m; };  /* single-overload shortcut */
    Object.defineProperty(m, 'implementation', {
        set: function (fn) {
            if (fn === null) {
                throw new Error('implementation restore not supported yet');
            }
            var orig = function () {
                return __gj_unwrap(__green_java_call_backup(
                    Array.prototype.slice.call(arguments)));
            };
            __green_java_hook(Java.__classIds[clsName], mid, name, sig,
                              isStatic ? 1 : 0, function () {
                /* Instance hooks receive the receiver as a raw handle id:
                 * wrap it so `this` is a proper instance wrapper. */
                var recvRaw = arguments[0];
                var recv = (typeof recvRaw === 'number' && recvRaw > 0)
                    ? __gj_wrap_instance(clsName, recvRaw)
                    : __gj_unwrap(recvRaw);
                var args = [];
                for (var i = 1; i < arguments.length; i++)
                    args.push(__gj_unwrap(arguments[i]));
                var self = __gj_hook_self(clsName,
                    (recv && recv.__id) || 0, m);
                if (recv && recv.__id) {
                    /* `this.method(...)` inside the implementation must
                     * reach the ORIGINAL: override it on this per-call
                     * wrapper (wrappers are fresh objects, no pollution). */
                    recv[m.__name] = function () {
                        return orig.apply(null, arguments);
                    };
                }
                var r = fn.apply(recv && recv.__id ? recv : self, args);
                __gj_hook_done();
                return r;
            });
        },
        get: function () { return undefined; }
    });
    return m;
}

function __gj_wrap_class(name, clsId, info) {
    var w = { __name: name, __clsId: clsId, __isClass: true };
    var byname = {};
    /* methods (dedupe name+sig from getMethods/getDeclaredMethods) */
    for (var i = 0; i < info.methods.length; i++) {
        var e = info.methods[i];
        var key = e.name + '.' + e.sig;
        if (byname[key]) continue;
        var mid = __green_java_get_method_id(clsId, e.name, e.sig, e['static'] ? 1 : 0);
        if (mid === 0) continue;
        var m = __gj_meth(mid, e.name, e.sig, e['static'], name);
        byname[key] = m;
        if (!w[e.name] || (e['static'] && !w[e.name].__static &&
                           !w[e.name].__group)) {
            w[e.name] = m;
        } else if (w[e.name] && !w[e.name].__group) {
            /* second overload for same name: build a dispatcher */
            (function (mn) {
                var first = w[mn];
                var disp = function () {
                    var pick = __gj_pick(disp.__group, arguments);
                    return pick.apply(null, arguments);
                };
                disp.__group = [first];
                disp.overload = function (sig) {
                    for (var k = 0; k < disp.__group.length; k++)
                        if (disp.__group[k].__sig === sig) return disp.__group[k];
                    throw new Error('no overload ' + sig);
                };
                Object.defineProperty(disp, 'implementation', {
                    set: function (fn) {
                        for (var k = 0; k < disp.__group.length; k++)
                            disp.__group[k].implementation = fn;
                    },
                    get: function () { return undefined; }
                });
                w[mn] = disp;
            })(e.name);
        }
        if (w[e.name] && w[e.name].__group) w[e.name].__group.push(m);
    }
    /* constructors */
    w.$new = function () {
        var args = [];
        for (var ai = 0; ai < arguments.length; ai++)
            args.push(arguments[ai]);
        var pick = null, bestScore = -1;
        for (var i = 0; i < info.ctors.length; i++) {
            var sig = info.ctors[i].sig;
            var st = __gj_argtypes(sig);
            if (st.length !== args.length) continue;
            var sc = __gj_score(st, args);
            if (sc > bestScore) { bestScore = sc; pick = sig; }
        }
        if (pick === null && info.ctors.length > 0)
            for (var i = 0; i < info.ctors.length; i++) {
                if (__gj_argcount(info.ctors[i].sig) === args.length) {
                    pick = info.ctors[i].sig;
                    break;
                }
            }
        if (pick === null && info.ctors.length > 0)
            pick = info.ctors[0].sig;
        if (pick === null) throw new Error('no constructor for ' + name);
        var cmid = __green_java_get_method_id(clsId, '<init>', pick, 0);
        if (cmid === 0) throw new Error('ctor <init>' + pick + ' not found');
        var id = __green_java_new_object(clsId, cmid, pick, args);
        return __gj_wrap_instance(name, id);
    };
    w.$dispose = function () {};
    return w;
}

function __gj_argcount(sig) {
    var d = sig.indexOf(')');
    var inner = sig.substring(1, d);
    var n = 0, i = 0;
    while (i < inner.length) {
        var c = inner[i];
        if (c === 'L') { while (inner[i] !== ';') i++; i++; }
        else if (c === '[') { i++; if (inner[i] === 'L') { while (inner[i] !== ';') i++; i++; } }
        else i++;
        n++;
    }
    return n;
}

function __gj_argtypes(sig) {
    var d = sig.indexOf(')');
    var inner = sig.substring(1, d);
    var t = [], i = 0;
    while (i < inner.length) {
        var c = inner[i];
        if (c === 'L') { while (inner[i] !== ';') i++; i++; t.push('L'); }
        else if (c === '[') { i++; if (inner[i] === 'L') { while (inner[i] !== ';') i++; } i++; t.push('L'); }
        else { i++; t.push(c); }
    }
    return t;
}

function __gj_score(sigTypes, args) {
    var score = 0;
    for (var i = 0; i < sigTypes.length; i++) {
        var t = sigTypes[i], a = args[i];
        if (a === null || a === undefined) { score += 1; continue; }
        var isStr = typeof a === 'string';
        var isNum = typeof a === 'number' || typeof a === 'bigint';
        var isObj = typeof a === 'object';
        if (t === 'L' || t === '[') {
            if (isStr || isObj) score += 2; else return -1;
        } else if (t === 'J') {
            if (isNum) score += 2; else return -1;
        } else if (t === 'F' || t === 'D') {
            if (isNum) score += 2; else return -1;
        } else if (t === 'C' || t === 'Z') {
            if (isNum && !isStr) score += 2;
            else if (isStr && a.length === 1) score += 1;
            else return -1;
        } else {  /* B S I */
            if (isNum) score += 2; else return -1;
        }
    }
    return score;
}

function __gj_pick(group, args) {
    var best = null, bestScore = -1;
    for (var i = 0; i < group.length; i++) {
        var st = __gj_argtypes(group[i].__sig);
        if (st.length !== args.length) continue;
        var sc = __gj_score(st, args);
        if (sc > bestScore) { bestScore = sc; best = group[i]; }
    }
    if (best === null) {
        var sigs = [];
        for (var i = 0; i < group.length; i++) sigs.push(group[i].__sig);
        throw new Error('no overload of ' + group[0].__name +
                        ' takes ' + args.length + ' argument(s): ' +
                        sigs.join(' '));
    }
    return best;
}

function __gj_unwrap(v) {
    if (v !== null && typeof v === 'object' &&
        v.__greenobj !== undefined) {
        var cls = v.__greencls;
        if (cls.charAt(0) === '[') return v;  /* arrays stay as markers */
        if (!Java.__classes[cls]) {
            try { Java.use(cls); } catch (e) { return v; }
        }
        return __gj_wrap_instance(cls, v.__greenobj);
    }
    return v;
}

function __gj_call(clsName, objId, mid, sig, isStatic, rawArgs) {
    var args = [];
    for (var i = 0; i < rawArgs.length; i++) args.push(rawArgs[i]);
    return __gj_unwrap(__green_java_call(Java.__classIds[clsName], objId,
                        mid, sig, isStatic ? 1 : 0, args));
}

/* Active-hook bookkeeping so `this.method(...)` inside implementations
 * calls the original. */
var __gj_active = 0;
function __gj_hook_self(clsName, recvId, m) {
    __gj_active++;
    var orig = function () {
        return __gj_unwrap(__green_java_call_backup(
            Array.prototype.slice.call(arguments)));
    };
    var self = { __recv: recvId, $className: clsName, $orig: orig };
    var klass = Java.__classes[clsName];
    if (klass) {
        for (var k in klass) {
            if (k[0] === '$' || k.indexOf('__') === 0) continue;
            (function (mn) {
                var slot = klass[mn];
                self[mn] = function () {
                    var a = [];
                    for (var i = 0; i < arguments.length; i++)
                        a.push(arguments[i]);
                    var m0 = slot && slot.__group
                        ? __gj_pick(slot.__group, a) : slot;
                    if (m0.__mid === m.__mid && m0.__sig === m.__sig)
                        /* The hooked method itself: invoke the ORIGINAL
                         * through this thread's backup ArtMethod. */
                        return orig.apply(null, a);
                    if (m0.__static)
                        return __gj_call(clsName, 0, m0.__mid, m0.__sig, 1, a);
                    return __gj_unwrap(__green_java_call(
                        Java.__classIds[clsName],
                        recvId, m0.__mid, m0.__sig, 0, a));
                };
            })(k);
        }
    }
    return self;
}
function __gj_hook_done() { if (__gj_active > 0) __gj_active--; }

/* Instance wrapper: obj.method(...) dispatches via the class table. */
function __gj_wrap_instance(clsName, objId) {
    var o = { __id: objId, __cls: clsName, __isInstance: true };
    var klass = Java.__classes[clsName];
    if (klass) {
        for (var k in klass) {
            if (k[0] === '$' || k.indexOf('__') === 0) continue;
            (function (mn) {
                var slot = klass[mn];
                if (slot && slot.__static) return;  /* instance only */
                if (slot && slot.__group) {
                    var allStatic = true;
                    for (var gi = 0; gi < slot.__group.length; gi++)
                        if (!slot.__group[gi].__static) allStatic = false;
                    if (allStatic) return;
                }
                o[mn] = function () {
                    var clsId = Java.__classIds[clsName];
                    var jargs = [];
                    for (var i = 0; i < arguments.length; i++)
                        jargs.push(arguments[i]);
                    var m0 = slot && slot.__group
                        ? __gj_pick(slot.__group, jargs) : slot;
                    return __gj_unwrap(__green_java_call(clsId, o.__id,
                        m0.__mid, m0.__sig, 0, jargs));
                };
            })(k);
        }
    }
    o.toString = function () { return __green_java_to_string(o.__id); };
    o.$dispose = function () { __green_java_delete_ref(o.__id); o.__id = 0; };
    return o;
}

/* Lazy availability probe (safe on non-JVM processes). */
Java.available = __green_java_available() ? true : false;
