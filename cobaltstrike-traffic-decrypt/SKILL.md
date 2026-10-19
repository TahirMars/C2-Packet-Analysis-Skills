---
name: cobaltstrike-traffic-decrypt
description: Recover Cobalt Strike Beacon session keys and decrypt Beacon metadata or full HTTP traffic. Use when a Beacon sample or stage must be parsed with 1768.py, when config item publickey must be converted to modulus or PEM, when weak RSA p and q have been recovered with YAFU, when encrypted cookie/metadata must be decrypted, or when a PCAP must be decrypted with cs-parse-http-traffic.py.
---

# Cobalt Strike Traffic Decrypt

Run every command from this skill directory.

## Workflow

1. Extract the Beacon config with `cs-1768/1768.py`.
2. Summarize the fields needed for decrypt with `scripts/recover_cs_keys.py config-summary`.
3. Choose a private-key path:
   - Known or leaked key: `cs-decrypt-metadata/cs-decrypt-metadata.py`
   - Weak modulus: factor with `cs-rsa/yafu-windows-generic.exe` or `cs-rsa/yafu-linux-generic`, then `scripts/recover_cs_keys.py metadata`
4. Reverse the malleable C2 cookie transform before decrypting metadata.
5. Decrypt the HTTP session with `cs-parse-http-traffic/cs-parse-http-traffic.py`.
6. Read [references/workflow.md](references/workflow.md) for the exact command sequence and transform notes.

## Operating Rules

- Treat the HTTP cookie as encrypted Beacon metadata only after removing the malleable C2 wrappers shown by `1768.py`.
- Prefer passing `rawkey` to `cs-parse-http-traffic.py`; that script derives AES and HMAC the same way Beacon does.
- Skip factorization if `1768.py`, `1768.json`, or another artifact already provides the private key.
- Use `scripts/recover_cs_keys.py` instead of the one-off files in `cs-rsa/`. Those original scripts stay as reference only.
- Use `cs-rsa/yafu-windows-generic.exe` on Windows and `cs-rsa/yafu-linux-generic` on Linux.

## Resources

- `scripts/recover_cs_keys.py`: Summarize 1768 JSON, convert the public key, rebuild a private key, and decrypt metadata.
- `cs-1768/1768.py`: Extract Beacon configuration. JSON output is the handoff format.
- `cs-decrypt-metadata/cs-decrypt-metadata.py`: Decrypt metadata with a hex key, `.cobaltstrike.beacon.keys`, or known keys from `cs-1768/1768.json`.
- `cs-parse-http-traffic/cs-parse-http-traffic.py`: Decrypt Beacon HTTP from a PCAP/PCAPNG.
- `cs-rsa/`: Bundled YAFU binaries plus the original RSA helper scripts.
- `references/workflow.md`: End-to-end command sequence.
