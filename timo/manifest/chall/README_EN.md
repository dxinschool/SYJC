# Manifest Player Notice

## Background

`Manifest` is an offline port terminal that supports login, roster registration, manifest updates, crate import, incident reporting, and sealed diagnostics.

## Attachment

- `/home/ctf/awd`

## Patch Rules

1. Only the '. text' section near the vulnerability point is allowed to be modified.
2. Total changed bytes must be <= 6.
3. File size and layout must stay identical; no new segments or re-linking.
4. Runs under a restricted user and sandbox; no new deps or syscalls.
5. Rate limit: max 2 submissions per 5 minutes.

## Submission

1. Place your patched ELF under `/tmp/`.
2. Run:

```
sudo /usr/local/bin/check /tmp/your_elf
```

- On success, it is deployed to `/home/ctf/awd`.
- On failure, only a generic failure message is returned.

