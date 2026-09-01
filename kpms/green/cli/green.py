#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
green.py -- cross-platform host CLI for `green server`.

Frida-style usage (after `adb forward tcp:27042 tcp:27042`, with
`green server` running on the device as root):

    python3 green.py ps [filter]
    python3 green.py attach -p PID -l script.js
    python3 green.py attach -f com.example.app -c "console.log('hi')"
    python3 green.py spawn com.example.app    # reserved, not implemented

Script console.log()/send() output is streamed live until Ctrl-C.
"""

import argparse
import os
import socket
import struct
import sys
import time

MAGIC = 0x31524747  # "GGR1"

T_LIST = 1
T_ATTACH = 2
T_SPAWN = 3
T_LOG = 0x80
T_RESULT = 0x81
T_PROCS = 0x82


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock):
    header = recv_exactly(sock, 12)
    magic, ftype, flags, length = struct.unpack("<IHHI", header)
    if magic != MAGIC:
        raise ConnectionError("bad frame magic 0x%x" % magic)
    payload = recv_exactly(sock, length) if length else b""
    return ftype, flags, payload


def send_frame(sock, ftype, payload=b""):
    sock.sendall(struct.pack("<IHHI", MAGIC, ftype, 0, len(payload)) + payload)


def encode_attach(pid, package, script):
    pkg = (package or "").encode()[:127].ljust(128, b"\0")
    has_pkg = 1 if package else 0
    return struct.pack("<iB128sI", pid, has_pkg, pkg, len(script)) + script


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
    if args.package:
        script = read_script(args)
        sock = connect(args)
        send_frame(sock, T_ATTACH, encode_attach(0, args.package, script))
    else:
        script = read_script(args)
        sock = connect(args)
        send_frame(sock, T_ATTACH, encode_attach(args.pid, None, script))

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
            (ok, length) = struct.unpack_from("<iI", payload, 0)
            msg = payload[8:8 + length].decode(errors="replace")
            tag = "+" if ok else "!"
            print("[%s] %s" % (tag, msg))
            if not ok:
                return 1
        else:
            pass


def read_script(args):
    if args.code is not None:
        return args.code.encode()
    if not args.script:
        die("attach needs exactly one of -l/-c")
    with open(args.script, "rb") as fh:
        return fh.read()


def cmd_spawn(args):
    sock = connect(args)
    pkg = args.package.encode()[:127].ljust(128, b"\0")
    send_frame(sock, T_SPAWN, pkg)
    while True:
        ftype, _, payload = recv_frame(sock)
        if ftype == T_RESULT:
            (ok, length) = struct.unpack_from("<iI", payload, 0)
            msg = payload[8:8 + length].decode(errors="replace")
            print("[%s] %s" % ("+" if ok else "!", msg))
            return 0 if ok else 1


def connect(args):
    sock = socket.create_connection((args.host, args.port), timeout=5)
    sock.settimeout(None)
    return sock


def die(msg):
    print("green.py: %s" % msg, file=sys.stderr)
    sys.exit(2)


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

    p_sp = sub.add_parser("spawn", help="spawn an app (reserved)")
    p_sp.add_argument("package")

    args = parser.parse_args()
    handlers = {"ps": cmd_list, "attach": cmd_attach, "spawn": cmd_spawn}
    try:
        sys.exit(handlers[args.command](args))
    except ConnectionError as exc:
        die(str(exc) + " (is `green server` running? adb forward set up?)")


if __name__ == "__main__":
    main()
