var Process = {
    id: __green_pid(),
    arch: 'arm64',
    platform: 'linux',
    pageSize: 4096,
    enumerateModulesSync: __green_modules
};
var Module = {
    enumerateModulesSync: __green_modules,
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
            var wname = 'write' + name.slice(5);
            NativePointer.prototype[wname] = function (value, offset) {
                var a = Number(this.__v) + (offset || 0);
                var b = new ArrayBuffer(size);
                var dv = new DataView(b);
                if (size === 8 && typeof value === 'bigint')
                    dv[getter.replace('get', 'set')](0, value, true);
                else if (size === 8)
                    dv[getter.replace('get', 'set')](0, BigInt(value), true);
                else
                    dv[getter.replace('get', 'set')](0, value, true);
                if (!__green_mem_write(a, b))
                    throw new Error('access violation writing at 0x' + a.toString(16));
            };
        })(name, rw[name][0], rw[name][1]);
    }
})();
NativePointer.prototype.readPointer = function () {
    return new NativePointer(this.readU64());
};
NativePointer.prototype.writePointer = function (v) {
    this.writeU64(new NativePointer(v).__v);
};
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
                ? function (retval) { var r = callbacks.onLeave(retval); return r === undefined ? retval : r; } : undefined);
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
