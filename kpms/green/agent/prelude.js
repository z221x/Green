var Process = {
    id: __green_pid(),
    arch: 'arm64',
    platform: 'linux',
    pageSize: 4096,
    pointerSize: 8,
    codeSigningPolicy: 'optional',
    enumerateModulesSync: __green_modules
};
Process.enumerateModules = function () {
    return __green_modules().map(__green_mod_upgrade);
};
function __green_mod_upgrade(m) {
    if (m.__upgraded) return m;
    m.__upgraded = true;
    m.base = new NativePointer(m.base);
    m.findExportByName = function (name) {
        return Module.findExportByName(m.name, name);
    };
    m.getExportByName = function (name) {
        return Module.getExportByName(m.name, name);
    };
    m.findSymbolByName = function (name) {
        var syms = m.enumerateSymbols();
        for (var i = 0; i < syms.length; i++)
            if (syms[i].name === name) return syms[i].address;
        return null;
    };
    m.getSymbolByName = m.findSymbolByName;
    m.enumerateImports = function () {
        return __green_module_list_imports(m.name).map(function (e) {
            return { name: e.name, address: new NativePointer(e.address),
                     module: m.name, type: 'function' };
        });
    };
    m.enumerateExports = function () {
        return __green_module_list_syms(m.name, 1).map(function (e) {
            return { name: e.name, address: new NativePointer(e.address),
                     type: 'function' };
        });
    };
    m.enumerateSymbols = function () {
        var dyn = __green_module_list_syms(m.name, 1);
        var full = dyn.length > 500 ? dyn : __green_module_list_syms(m.name, 0);
        return full.map(function (e) {
            return { name: e.name, address: new NativePointer(e.address),
                     type: 'function' };
        });
    };
    return m;
}
Process.findModuleByName = function (name) {
    var ms = __green_modules();
    for (var i = 0; i < ms.length; i++)
        if (ms[i].name === name) return __green_mod_upgrade(ms[i]);
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
    enumerateModules: function () {
        return __green_modules().map(__green_mod_upgrade);
    },
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
            try {
                this.__v = BigInt.asUintN(64, BigInt(t));
                return;
            } catch (e) {
                log('NativePointer: unparseable: ' + JSON.stringify(String(v).slice(0, 40)));
                throw e;
            }
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
        if (Array.isArray(buf)) {
            var ab = new Uint8Array(buf).buffer;
            if (!__green_mem_write(Number(this.__v), ab))
                throw new Error('access violation writing ' + buf.length + ' bytes');
            return this;
        }
        if (!__green_mem_write(Number(this.__v), buf))
            throw new Error('access violation writing ' +
                (buf && buf.byteLength) + ' bytes');
        return this;
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
/* frida-compatible aliases */
NativePointer.prototype.readInt = function (o) { return this.readS32(o); };
NativePointer.prototype.readUInt = function (o) { return this.readU32(o); };
NativePointer.prototype.readLong = function (o) { return this.readS64(o); };
NativePointer.prototype.readULong = function (o) { return this.readU64(o); };
NativePointer.prototype.writeInt = function (v, o) { return this.writeS32(v, o); };
NativePointer.prototype.writeUInt = function (v, o) { return this.writeU32(v, o); };
NativePointer.prototype.writeLong = function (v, o) { return this.writeS64(v, o); };
NativePointer.prototype.writeULong = function (v, o) { return this.writeU64(v, o); };
NativePointer.prototype.readPointer = function () {
    return new NativePointer(BigInt.asUintN(64, this.readU64()) &
        0x00ffffffffffffffn);
};
NativePointer.prototype.writePointer = function (v) {
    this.writeU64(new NativePointer(v).__v);
    return this;
};
function ptr(v) { return new NativePointer(v); }
var NULL = ptr(0);
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
    if (type === 'pointer')
        raw &= 0x00ffffffffffffffn;   /* strip MTE/PAC tag */
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

/* ---- frida-java-bridge host compatibility layer -------------------- */
function int64(v) { return new Int64(v); }
function uint64(v) { return new UInt64(v); }

Process.myUid = function () { return __green_getuid(); };
Process.SYSTEM_UID = int64(1000);

/* Linker-namespace-proof fallback for findExportByName(null, ...). */
(function () {
    var origFind = Module.findExportByName;
    var origGet = Module.getExportByName;
    Module.findExportByName = function (moduleName, exportName) {
        if (moduleName === null || moduleName === undefined) {
            var a = __green_find_export_any(exportName);
            return a === null ? null : new NativePointer(a);
        }
        var r = origFind.call(Module, moduleName, exportName);
        if (r !== null && r !== undefined) return r;
        var b = __green_find_export_any(exportName);
        return b === null ? null : new NativePointer(b);
    };
    Module.getExportByName = function (moduleName, exportName) {
        var r = Module.findExportByName(moduleName, exportName);
        if (r === null) throw new Error('unable to find export ' + exportName);
        return r;
    };
    Module.getGlobalExportByName = function (exportName) {
        var r = Module.findExportByName(null, exportName);
        if (r === null) throw new Error('unable to find global export ' + exportName);
        return r;
    };
    Module.findGlobalExportByName = function (exportName) {
        return Module.findExportByName(null, exportName);
    };
    Module.getBaseAddress = Module.getBaseAddress || Module.prototype && undefined;
})();

/* Memory additions ------------------------------------------------- */
Memory.allocUtf8String = function (str) {
    var b = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 0x80) b.push(c);
        else {
            b.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
        }
    }
    b.push(0);
    var p = Memory.alloc(b.length);
    p.writeByteArray(b);
    return p;
};
Memory.allocUtf16String = function (str) {
    var b = [];
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        b.push(c & 0xff, (c >> 8) & 0xff);
    }
    b.push(0, 0);
    var p = Memory.alloc(b.length);
    p.writeByteArray(b);
    return p;
};
Memory.dup = function (p, size) {
    var q = Memory.alloc(size);
    Memory.copy(q, p, size);
    return q;
};
Memory.copy = function (dst, src, size) {
    var d = new NativePointer(dst), s = new NativePointer(src);
    for (var off = 0; off < size; off += 4096) {
        var n = Math.min(4096, size - off);
        var chunk = new NativePointer(Number(s.__v) + off).readByteArray(n);
        new NativePointer(Number(d.__v) + off).writeByteArray(chunk);
    }
};

/* Match-pattern support: 'de ad ?? ef' (also '??' wildcards). */
function __green_parse_pattern(pattern) {
    var parts = pattern.split(/\s+/);
    var pat = [];
    for (var i = 0; i < parts.length; i++) {
        var t = parts[i];
        if (t === '') continue;
        if (t === '??' || t === '**') pat.push(-1);
        else pat.push(parseInt(t, 16));
    }
    return pat;
}
Memory.scanSync = function (base, size, pattern) {
    var p = new NativePointer(base);
    var pat = __green_parse_pattern(pattern);
    var matches = [];
    var CHUNK = 65536;
    for (var off = 0; off < size; off += CHUNK) {
        var n = Math.min(CHUNK, size - off);
        var bytes;
        try {
            bytes = new NativePointer(Number(p.__v) + off).readByteArray(n);
        } catch (e) { continue; }
        outer:
        for (var i = 0; i + pat.length <= n; i++) {
            for (var j = 0; j < pat.length; j++) {
                if (pat[j] >= 0 && bytes[i + j] !== pat[j]) continue outer;
            }
            matches.push({ address: new NativePointer(Number(p.__v) + off + i),
                           size: pat.length });
            if (matches.length > 4096) return matches;
        }
    }
    return matches;
};
Memory.scan = function (base, size, pattern, callbacks) {
    var matches = Memory.scanSync(base, size, pattern);
    for (var i = 0; i < matches.length; i++) {
        if (callbacks.onMatch)
            callbacks.onMatch(matches[i].address, matches[i].size);
    }
    if (callbacks.onComplete) callbacks.onComplete();
};

Memory.patchCode = function (address, size, apply) {
    var p = new NativePointer(address);
    var page = 4096;
    /* NOTE: JS bitwise ops are 32-bit — use division for 48-bit VAs. */
    var start = Math.floor(Number(p.__v) / page) * page;
    var end = Math.floor((Number(p.__v) + Number(size) + page - 1) / page) * page;
    __green_mprotect(start, end - start, 7);          /* RWX while writing */
    try {
        apply(p);
    } finally {
        __green_mprotect(start, end - start, 5);      /* back to R-X */
    }
    __green_icache_flush(start, end - start);
};

/* Script runtime shims --------------------------------------------- */
var __green_ticks = [];
Script = {
    nextTick: function (fn) { __green_ticks.push(fn); },
    pin: function () {}, unpin: function () {},
    bindWeak: function (obj, cb) {
        /* Strong-ref registry: destructors never fire (leak-only). */
        if (!Script.__weak) Script.__weak = [];
        Script.__weak.push([obj, cb]);
        return Script.__weak.length - 1;
    },
    unbindWeak: function (id) {
        if (Script.__weak && Script.__weak[id]) Script.__weak[id] = null;
    },
    setGlobalAccessHandler: function () {}
};
function __green_pump_ticks() {
    var n = __green_ticks.length;
    for (var i = 0; i < n; i++) {
        var fn = __green_ticks[i];
        try { fn(); } catch (e) { log('tick error: ' + e); }
    }
    __green_ticks.splice(0, n);
}

/* CModule over gum's TCC backend ------------------------------------ */
function CModule(source, symbols) {
    var h = __green_cmodule_new(source);
    if (typeof h !== 'number') throw new Error('CModule compile failed');
    var names = symbols ? Object.getOwnPropertyNames(symbols) : [];
    for (var i = 0; i < names.length; i++) {
        var v = symbols[names[i]];
        __green_cmodule_add_symbol(h, names[i],
            v === null || v === undefined ? 0
                : Number(new NativePointer(v.__v !== undefined ? v.__v : v).__v));
    }
    if (__green_cmodule_link(h) !== true)
        throw new Error('CModule link failed');
    this.__h = h;
    var self = this;
    return new Proxy(this, {
        get: function (t, name) {
            if (typeof name !== 'string') return t[name];
            if (name in t) return t[name];
            var a = __green_cmodule_get(h, name);
            return a === 0 ? undefined : new NativePointer(a);
        }
    });
}

/* Arm64Writer over gum C API (subset used by frida-java-bridge). */
var ARM64_REGS = {};
(function () {
    /* capstone v6 aarch64 enums */
    for (var i = 0; i <= 30; i++) ARM64_REGS['x' + i] = 218 + i;
    ARM64_REGS.sp = 5;
    ARM64_REGS.xzr = 9;
    ARM64_REGS.fp = ARM64_REGS.x29;
    ARM64_REGS.lr = ARM64_REGS.x30;
    for (var i = 0; i <= 30; i++) ARM64_REGS['w' + i] = 187 + i;
    ARM64_REGS.wzr = 8;
    for (var i = 0; i <= 31; i++) {
        ARM64_REGS['d' + i] = 43 + i;
        ARM64_REGS['q' + i] = 123 + i;
        ARM64_REGS['s' + i] = 155 + i;
    }
})();
var ARM64_CCS = { eq:1,ne:2,hs:3,cs:3,lo:4,cc:4,mi:5,pl:6,vs:7,vc:8,
                  hi:9,ls:10,ge:11,lt:12,gt:13,le:14,al:15,nv:16 };
function __a64r(r) {
    if (typeof r === 'number') return r;
    var v = ARM64_REGS[String(r).toLowerCase()];
    if (v === undefined) throw new Error('bad register: ' + r);
    return v;
}
function Arm64Writer(code, options) {
    this.__h = __green_a64w_new(Number(new NativePointer(code).__v));
    this.__labels = {};
    this.__nextLabel = 1;
    this.pc = options && options.pc !== undefined
        ? new NativePointer(options.pc) : ptr(code);
    this.__defineGetter__('offset', function () {
        return __green_a64w(this.__h, 29);
    });
    var self = this;
    this.putPushRegReg = function (a, b) { __green_a64w(this.__h, 1, __a64r(a), __a64r(b)); };
    this.putPopRegReg = function (a, b) { __green_a64w(this.__h, 2, __a64r(a), __a64r(b)); };
    this.putLabel = function (name) {
        var id = this.__nextLabel++;
        this.__labels[name] = id;
        __green_a64w(this.__h, 3, id);
    };
    this.__label = function (name) {
        if (this.__labels[name] === undefined) this.__labels[name] = this.__nextLabel++;
        return this.__labels[name];
    };
    this.putBCondLabel = function (cc, name) {
        __green_a64w(this.__h, 4, ARM64_CCS[cc], this.__label(name));
    };
    this.putBCondLabelWide = this.putBCondLabel;
    this.putLdrRegAddress = function (r, addr) {
        __green_a64w(this.__h, 5, __a64r(r), Number(new NativePointer(addr).__v));
    };
    this.putStrRegRegOffset = function (a, b, off) {
        __green_a64w(this.__h, 6, __a64r(a), __a64r(b), off);
    };
    this.putLdrRegRegOffset = function (a, b, off) {
        __green_a64w(this.__h, 7, __a64r(a), __a64r(b), off);
    };
    this.putMovRegReg = function (a, b) { __green_a64w(this.__h, 8, __a64r(a), __a64r(b)); };
    this.putMovRegRegOffsetPtr = function (a, b, off) {
        __green_a64w(this.__h, 9, __a64r(a), __a64r(b), off);
    };
    this.putRet = function () { __green_a64w(this.__h, 10); };
    this.putBrReg = function (r) { __green_a64w(this.__h, 11, __a64r(r)); };
    this.putPushRegs = function (regs) {
        var rs = regs.map(function (r) { return __a64r(r); });
        __green_a64w(this.__h, 12, rs);
    };
    this.putPopRegs = function (regs) {
        var rs = regs.map(function (r) { return __a64r(r); });
        __green_a64w(this.__h, 13, rs);
    };
    this.putPushAllXRegisters = function () { __green_a64w(this.__h, 32); };
    this.putPopAllXRegisters = function () { __green_a64w(this.__h, 33); };
    this.putBytes = function (bytes) {
        var b = bytes instanceof ArrayBuffer ? bytes : new Uint8Array(bytes).buffer;
        __green_a64w(this.__h, 14, b);
    };
    this.putBranchAddress = function (addr) {
        __green_a64w(this.__h, 15, Number(new NativePointer(addr).__v));
    };
    this.putCallAddressWithArguments = function (addr, args) {
        __green_a64w(this.__h, 16, Number(new NativePointer(addr).__v), args);
    };
    this.putCallAddressWithAlignedArguments = function (addr, args) {
        __green_a64w(this.__h, 16, Number(new NativePointer(addr).__v), args);
    };
    this.putCallAddress = function (addr) {
        __green_a64w(this.__h, 16, Number(new NativePointer(addr).__v), []);
    };
    this.putCbnzRegLabel = function (r, name) {
        __green_a64w(this.__h, 17, __a64r(r), this.__label(name));
    };
    this.putCbzRegLabel = function (r, name) {
        __green_a64w(this.__h, 18, __a64r(r), this.__label(name));
    };
    this.putTbnzRegImmLabel = function (r, imm, name) {
        __green_a64w(this.__h, 19, __a64r(r), imm, this.__label(name));
    };
    this.putTbzRegImmLabel = function (r, imm, name) {
        __green_a64w(this.__h, 20, __a64r(r), imm, this.__label(name));
    };
    this.putAddRegRegImm = function (a, b, imm) {
        __green_a64w(this.__h, 21, __a64r(a), __a64r(b), imm);
    };
    this.putAddRegImm = this.putAddRegRegImm;
    this.putSubRegRegImm = function (a, b, imm) {
        __green_a64w(this.__h, 22, __a64r(a), __a64r(b), imm);
    };
    this.putSubRegImm = this.putSubRegRegImm;
    this.putCmpRegReg = function (a, b) { __green_a64w(this.__h, 23, __a64r(a), __a64r(b)); };
    this.putCmpRegImm = this.putCmpRegReg;
    this.putAndRegReg = function (a, b) { __green_a64w(this.__h, 24, __a64r(a), __a64r(b)); };
    this.putMrsRegReg = function (a, sys) { __green_a64w(this.__h, 25, __a64r(a), sys); };
    this.putMsrRegReg = function (sys, r) { __green_a64w(this.__h, 26, sys, __a64r(r)); };
    this.putBlImm = function (target) {
        __green_a64w(this.__h, 27, Number(new NativePointer(target).__v));
    };
    this.putBLabel = function (name) { __green_a64w(this.__h, 30, this.__label(name)); };
    this.putJmpAddress = this.putBranchAddress;
    this.putJccShortLabel = this.putBCondLabel;
    this.putJccNearLabel = this.putBCondLabel;
    this.putJmpNearLabel = this.putBLabel;
    this.flush = function () { __green_a64w(this.__h, 28); };
    this.dispose = this.clear = function () { __green_a64w(this.__h, 99); };
}
