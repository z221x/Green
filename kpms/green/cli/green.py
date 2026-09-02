#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
green.py -- cross-platform host CLI for `green server`.

All device functionality is driven from here; the device binary only runs
the daemon (frida-server style).  After `adb forward tcp:27042 tcp:27042`
with `green` running as root on the device:

    python3 green.py ps [filter]
    python3 green.py attach -p PID -l script.js
    python3 green.py attach -f com.example.app -c "console.log('hi')"
    python3 green.py spawn com.example.app          # reserved

    python3 green.py shadow maps   -p PID [filter]
    python3 green.py shadow count  -p PID
    python3 green.py shadow patch  -p PID (-a ADDR | -b LIB -o OFF) -x HEX
    python3 green.py shadow nop    -p PID -a ADDR [-n INSNS]
    python3 green.py shadow branch -p PID -a ADDR -t TARGET
    python3 green.py shadow release -p PID [-a ADDR]

Script console.log()/send() output is streamed live until Ctrl-C.
"""

import argparse
import socket
import struct
import sys

MAGIC = 0x31524747  # "GGR1"

T_LIST = 1
T_ATTACH = 2
T_SPAWN = 3
T_SHADOW_PATCH = 4
T_SHADOW_RELEASE = 5
T_SHADOW_COUNT = 6
T_SOLIST = 7
T_EVAL = 8
T_KILL = 9
T_LOG = 0x80
T_RESULT = 0x81
T_PROCS = 0x82
T_MODULES = 0x83

A64_NOP = 0xD503201F


# ---- framing ---------------------------------------------------------------

def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock):
    magic, ftype, flags, length = struct.unpack("<IHHI", recv_exactly(sock, 12))
    if magic != MAGIC:
        raise ConnectionError("bad frame magic 0x%x" % magic)
    payload = recv_exactly(sock, length) if length else b""
    return ftype, flags, payload


def send_frame(sock, ftype, payload=b""):
    sock.sendall(struct.pack("<IHHI", MAGIC, ftype, 0, len(payload)) + payload)


def recv_result(sock):
    """Returns (ok, value, message).  Frame: i32 ok, u32 pad, i64 value,
    u32 msg_len, msg."""
    ftype, _, payload = recv_frame(sock)
    if ftype != T_RESULT:
        raise ConnectionError("expected RESULT, got type 0x%x" % ftype)
    ok, _pad, value, length = struct.unpack_from("<iIqI", payload[:20])
    return ok, value, payload[20:20 + length].decode(errors="replace")


def connect(args):
    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.settimeout(None)
    return sock


def die(msg):
    print("green.py: %s" % msg, file=sys.stderr)
    sys.exit(2)


# ---- process commands -------------------------------------------------------

def encode_attach(pid, package, script):
    pkg = (package or "").encode()[:127].ljust(128, b"\0")
    return struct.pack("<iB128sI", pid or 0, 1 if package else 0, pkg,
                       len(script)) + script


def read_script(args):
    if args.code is not None:
        return args.code.encode()
    if not args.script:
        die("attach needs exactly one of -l/-c")
    with open(args.script, "rb") as fh:
        return fh.read()


def cmd_list(args):
    sock = connect(args)
    send_frame(sock, T_LIST)
    _, _, payload = recv_frame(sock)
    (count,) = struct.unpack_from("<I", payload, 0)
    off = 4
    rows = []
    for _ in range(count):
        (pid,) = struct.unpack_from("<i", payload, off)
        (name_len,) = struct.unpack_from("<H", payload, off + 4)
        name = payload[off + 6:off + 6 + name_len].decode(errors="replace")
        off += 6 + name_len
        rows.append((pid, name))
    sock.close()
    for pid, name in rows:
        if args.filter and args.filter not in name and str(pid) != args.filter:
            continue
        print("%-8d %s" % (pid, name))
    print("%d process(es)" % len(rows))


def cmd_attach(args):
    script = read_script(args)
    sock = connect(args)
    send_frame(sock, T_ATTACH, encode_attach(args.pid, args.package, script))

    # Stream logs; the RESULT frame ends the load phase, afterwards keep
    # streaming until Ctrl-C.
    while True:
        try:
            ftype, _, payload = recv_frame(sock)
        except (ConnectionError, KeyboardInterrupt):
            print("\n[*] detached")
            return 0
        if ftype == T_LOG:
            (pid, length) = struct.unpack_from("<iI", payload, 0)
            text = payload[8:8 + length].decode(errors="replace")
            sys.stdout.write("[%d] %s\n" % (pid, text.rstrip("\n")))
            sys.stdout.flush()
        elif ftype == T_RESULT:
            ok = struct.unpack_from("<i", payload, 0)[0]
            length = struct.unpack_from("<I", payload, 16)[0]
            msg = payload[20:20 + length].decode(errors="replace")
            print("[%s] %s" % ("+" if ok else "!", msg))
            if not ok:
                return 1
            if args.repl or sys.stdin.isatty():
                return repl_loop(sock, args)


def repl_loop(sock, args):
    """Frida-style interactive loop: expressions are evaluated in the
    target's persistent QuickJS context; script logs stream meanwhile."""
    import threading

    done = threading.Event()

    def reader():
        while not done.is_set():
            try:
                ftype, _, payload = recv_frame(sock)
            except Exception:
                break
            if ftype == T_LOG:
                (pid, length) = struct.unpack_from("<iI", payload, 0)
                text = payload[8:8 + length].decode(errors="replace")
                sys.stdout.write("[%d] %s\n" % (pid, text.rstrip("\n")))
                sys.stdout.flush()
            elif ftype == T_RESULT:
                ok = struct.unpack_from("<i", payload, 0)[0]
                length = struct.unpack_from("<I", payload, 16)[0]
                msg = payload[20:20 + length].decode(errors="replace")
                print("[%s] %s" % ("+" if ok else "!", msg))
                sys.stdout.flush()
            elif ftype == T_PROCS:
                pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    print("[*] REPL ready -- type an expression, or exit/quit to detach")
    while True:
        try:
            line = input("green> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        line = line.strip()
        if not line:
            continue
        if line in ("exit", "quit", ".exit"):
            break
        code = ("(function(){ var __r; try { __r = eval(%s); }"
                " catch (e) { return 'Error: ' + e.message; }"
                " return typeof __r === 'object' && __r !== null ?"
                " JSON.stringify(__r) : String(__r); })()" %
                __import__("json").dumps(line))
        send_frame(sock, T_EVAL, struct.pack("<iI", args.pid, len(code)) +
                   code.encode())
    done.set()
    return 0


def cmd_eval(args):
    code = args.code if args.code else read_script(args).decode()
    sock = connect(args)
    payload = struct.pack("<iI", args.pid, len(code)) + code.encode()
    send_frame(sock, T_EVAL, payload)
    while True:
        ftype, _, pl = recv_frame(sock)
        if ftype == T_LOG:
            (pid, length) = struct.unpack_from("<iI", pl, 0)
            text = pl[8:8 + length].decode(errors="replace")
            sys.stdout.write("[%d] %s\n" % (pid, text.rstrip("\n")))
            sys.stdout.flush()
        elif ftype == T_RESULT:
            ok = struct.unpack_from("<i", pl, 0)[0]
            length = struct.unpack_from("<I", pl, 16)[0]
            msg = pl[20:20 + length].decode(errors="replace")
            print("[%s] %s" % ("+" if ok else "!", msg))
            return 0 if ok else 1


def cmd_kill(args):
    sock = connect(args)
    send_frame(sock, T_KILL, struct.pack("<i", args.pid))
    ok, _, msg = recv_result(sock)
    sock.close()
    print("[%s] %s" % ("+" if ok else "!", msg))
    return 0 if ok else 1


def cmd_spawn(args):
    sock = connect(args)
    send_frame(sock, T_SPAWN, args.package.encode()[:127].ljust(128, b"\0"))
    ok, _, msg = recv_result(sock)
    print("[%s] %s" % ("+" if ok else "!", msg))
    return 0 if ok else 1


# ---- shadow commands --------------------------------------------------------

def parse_hex_bytes(hexstr):
    clean = "".join(c for c in hexstr if c not in " :_,")
    if not clean or len(clean) % 2:
        die("invalid hex string")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        die("invalid hex string")


def make_branch(pc, target):
    if pc % 4 or target % 4:
        die("branch addresses must be 4-byte aligned")
    if target >= pc:
        distance = target - pc
        if distance > ((1 << 25) - 1) << 2:
            die("branch target out of range (+128MB)")
        imm = distance >> 2
    else:
        distance = pc - target
        if distance > (1 << 25) << 2:
            die("branch target out of range (-128MB)")
        imm = -(distance >> 2)
    return struct.pack("<I", 0x14000000 | (imm & 0x03FFFFFF))


def resolve_addr(sock, args):
    """-a ADDR directly, or -b LIB -o OFFSET via the target solist."""
    if args.addr is not None:
        return args.addr
    if not args.lib:
        die("needs -a ADDR or -b LIB -o OFFSET")
    send_frame(sock, T_SOLIST,
               struct.pack("<iB128s", args.pid, 0, b"\0" * 128))
    ftype, _, payload = recv_frame(sock)
    if ftype != T_MODULES:
        die("module enumeration failed")
    (count,) = struct.unpack_from("<I", payload, 0)
    off = 4
    base = None
    for _ in range(count):
        (mbase, size) = struct.unpack_from("<QQ", payload, off)
        (name_len,) = struct.unpack_from("<H", payload, off + 16)
        name = payload[off + 18:off + 18 + name_len].decode(errors="replace")
        off += 18 + name_len
        if name == args.lib or name.endswith("/" + args.lib):
            base = mbase
            break
    if base is None:
        die("module not found in solist: %s" % args.lib)
    return base + args.off


def cmd_shadow_maps(args):
    sock = connect(args)
    send_frame(sock, T_SOLIST,
               struct.pack("<iB128s", args.pid, 0, b"\0" * 128))
    ftype, _, payload = recv_frame(sock)
    sock.close()
    if ftype != T_MODULES:
        die("solist enumeration failed")
    (count,) = struct.unpack_from("<I", payload, 0)
    off = 4
    shown = 0
    for _ in range(count):
        (base, size) = struct.unpack_from("<QQ", payload, off)
        (name_len,) = struct.unpack_from("<H", payload, off + 16)
        name = payload[off + 18:off + 18 + name_len].decode(errors="replace")
        off += 18 + name_len
        if args.filter and args.filter not in name:
            continue
        print("0x%012lx 0x%-8lx %s" % (base, size, name))
        shown += 1
    print("%d module(s)" % shown)


def cmd_shadow_count(args):
    sock = connect(args)
    send_frame(sock, T_SHADOW_COUNT, struct.pack("<i", args.pid))
    ok, value, msg = recv_result(sock)
    sock.close()
    if not ok:
        die("shadow count failed: %s" % msg)
    print("pid %d has %d shadow page(s)" % (args.pid, value))


def cmd_shadow_patch(args):
    sock = connect(args)
    addr = resolve_addr(sock, args)
    if args.nops:
        data = struct.pack("<I", A64_NOP) * args.nops
    elif args.branch_target is not None:
        data = make_branch(addr, args.branch_target)
    else:
        data = parse_hex_bytes(args.hex)
    if len(data) > 4096:
        die("patch too large (max 4096)")
    send_frame(sock, T_SHADOW_PATCH,
               struct.pack("<iIQ", args.pid, len(data), addr) + data)
    ok, _, msg = recv_result(sock)
    sock.close()
    print("[%s] %s (pid %d @ 0x%x, %d bytes)" %
          ("+" if ok else "!", msg, args.pid, addr, len(data)))
    return 0 if ok else 1


def cmd_shadow_release(args):
    sock = connect(args)
    addr = args.addr if args.addr is not None else 0
    send_frame(sock, T_SHADOW_RELEASE, struct.pack("<iiQ", args.pid, 0, addr))
    ok, value, msg = recv_result(sock)
    sock.close()
    print("[%s] %s (%d page(s))" % ("+" if ok else "!", msg, value))
    return 0 if ok else 1


# ---- entry ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="green.py",
                                     description="Host CLI for green server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=27042)
    sub = parser.add_subparsers(dest="command", required=True)

    p_ps = sub.add_parser("ps", help="list processes on the device")
    p_ps.add_argument("filter", nargs="?", default="")

    p_att = sub.add_parser("attach", help="attach and run a hook script")
    target = p_att.add_mutually_exclusive_group(required=True)
    target.add_argument("-p", "--pid", type=int)
    target.add_argument("-f", "--package")
    src = p_att.add_mutually_exclusive_group(required=True)
    src.add_argument("-l", "--script", help="hook script file (host path)")
    src.add_argument("-c", "--code", help="inline JS hook code")
    p_att.add_argument("--repl", action="store_true",
                       help="enter interactive REPL after loading")

    p_sp = sub.add_parser("spawn", help="spawn an app (reserved)")
    p_sp.add_argument("package")

    p_ev = sub.add_parser("eval", help="evaluate a JS expression in a target")
    p_ev.add_argument("-p", "--pid", type=int, required=True)
    grp_ev = p_ev.add_mutually_exclusive_group(required=True)
    grp_ev.add_argument("-c", "--code")
    grp_ev.add_argument("-l", "--script")

    p_ki = sub.add_parser("kill", help="kill a process on the device")
    p_ki.add_argument("-p", "--pid", type=int, required=True)

    p_sh = sub.add_parser("shadow", help="hidden patch / hook operations")
    sh = p_sh.add_subparsers(dest="shadow_command", required=True)

    p_maps = sh.add_parser("maps", help="enumerate modules via the solist")
    p_maps.add_argument("-p", "--pid", type=int, required=True)
    p_maps.add_argument("filter", nargs="?", default="")

    p_count = sh.add_parser("count", help="count shadow pages of a process")
    p_count.add_argument("-p", "--pid", type=int, required=True)

    def common_addr(p):
        grp = p.add_mutually_exclusive_group(required=True)
        grp.add_argument("-a", "--addr", type=lambda x: int(x, 0))
        grp.add_argument("-b", "--lib", help="library name (solist lookup)")
        p.add_argument("-o", "--off", type=lambda x: int(x, 0), default=0)

    p_patch = sh.add_parser("patch", help="write bytes to the shadow page")
    p_patch.add_argument("-p", "--pid", type=int, required=True)
    common_addr(p_patch)
    grp = p_patch.add_mutually_exclusive_group(required=True)
    grp.add_argument("-x", "--hex", help="instruction hex (little-endian)")
    grp.add_argument("-n", "--nops", type=int,
                     help="write N ARM64 NOP instructions")
    grp.add_argument("-t", "--branch-target", type=lambda x: int(x, 0),
                     help="encode a B <target> jump")

    p_release = sh.add_parser("release", help="release shadow page(s)")
    p_release.add_argument("-p", "--pid", type=int, required=True)
    p_release.add_argument("-a", "--addr", type=lambda x: int(x, 0),
                           help="omit to release every shadow page")

    args = parser.parse_args()
    handlers = {
        "ps": cmd_list,
        "attach": cmd_attach,
        "spawn": cmd_spawn,
        "eval": cmd_eval,
        "kill": cmd_kill,
        "shadow": {
            "maps": cmd_shadow_maps,
            "count": cmd_shadow_count,
            "patch": cmd_shadow_patch,
            "release": cmd_shadow_release,
        },
    }
    handler = handlers[args.command]
    if isinstance(handler, dict):
        handler = handler.get(args.shadow_command)
        if handler is None:
            die("unknown shadow command (use maps/count/patch/release)")
    try:
        sys.exit(handler(args))
    except ConnectionError as exc:
        die(str(exc) + " (is `green` running on the device? adb forward set?)")


if __name__ == "__main__":
    main()
