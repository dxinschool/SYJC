# eznote vulnerabilities

## Command injection in create_note_dir (PATCHED - does not work)

**Location**: [eznote/chall](eznote/chall), function `create_note_dir` uses `system("mkdir -p '%s/%s/'")` with user-controlled `username`.

**Issue**: The original description claimed double quotes were used, but **this binary uses SINGLE quotes** (`'%s/%s/'`). In bash, single quotes prevent ALL shell expansion including `$()`, backticks, and variable substitution. Therefore, command injection via username does NOT work.

**Notes**:
- USERNAME_BLACKLIST: `"` `'` `.` (hex: 0x22 0x27 0x2e)
- The blacklist prevents breaking out of single quotes (need `'` to escape)
- This appears to be a patched/hardened version of the challenge

## Stack canary overwrite in note name input (PATCHED - limited impact)

**Location**: [eznote/chall](eznote/chall), function `main` reads the note name for options 3/4.

**Issue**: The note name buffer is at `rbp-0x50`. The `read()` call uses size 0x50 (80 bytes), writing from `rbp-0x50` to `rbp-0x01`.

The stack canary is at `rbp-0x08`, so bytes 0x48-0x4F of our input overwrite the 8-byte canary.

**However**, this is a PATCHED version:
- Original vulnerable binary likely used `read(0, buf, 0x60)` (96 bytes)
- That would reach saved_rbp (at rbp+0x00) and ret_addr (at rbp+0x08)
- Current binary uses only 0x50 bytes - stops at rbp-0x01
- We can corrupt canary but CANNOT overwrite return address

**Impact**: Denial of service only (program crashes on exit due to canary mismatch). 
No code execution possible since return address is unreachable.

**Notes**:
- Stack layout: `[buffer 0x48][canary 8][saved_rbp 8][ret_addr 8]`
- Our write range: `[buffer 0x48][canary first 8 bytes]`
- Gap to saved_rbp: 0 bytes, but we stop 1 byte short

## Path traversal blocked

**Location**: username and notename validation

**Issue**: Could theoretically traverse to `/flag` via `../../` sequences, but:
- Username blacklist includes `.` (period) - blocks `..` traversal
- Notename only allows hex chars (0-9, a-f)

**Notes**:
- Username CAN contain `/` for creating nested directories
- No symlink creation capability within the program

---

## Analysis: Patched vs Unpatched Binary

This appears to be a **PATCHED** challenge binary. The unpatched version likely had:

| Vulnerability | Unpatched | Patched (current) |
|--------------|-----------|-------------------|
| mkdir quotes | Double `"` | Single `'` |
| Note read size | 0x60 (96 bytes) | 0x50 (80 bytes) |
| Command injection | ✅ Exploitable | ❌ Blocked |
| Stack overflow | ✅ Full ROP | ❌ Canary only |

### Exploits for UNPATCHED server:

1. **Command injection** ([solve_cmd_injection.py](solve_cmd_injection.py)):
   - Username: `$(cat /flag >&2)`
   - Select option 2 (create note dir)
   - Flag appears in stderr/stdout

2. **Stack overflow** (if 0x60 read):
   - Brute-force canary (fork-based server)
   - ROP to open/read/write /flag
   - Seccomp allows file I/O syscalls

---

## Testing Results (172.29.42.42:1000)

Server confirmed PATCHED:
- `$(echo CMDEXEC)` as username → Shows empty in "Hello , what do you..." 
- Command substitution NOT evaluated (single quotes confirmed)
- All command injection payloads produce empty username

### Available Scripts

| Script | Purpose | Works on Patched? |
|--------|---------|-------------------|
| [solve_cmd_injection.py](solve_cmd_injection.py) | Command injection via `$()` |
| [solve_note_bof.py](solve_note_bof.py) | Stack overflow PoC | Crash only (DoS) |

### AWD Strategy

Since this is an AWD challenge:
1. **Defense**: Your binary should already be patched (single quotes + 0x50 read)
2. **Attack**: Try exploits against OTHER teams who haven't patched
3. Other teams' servers may still have double quotes → command injection works
