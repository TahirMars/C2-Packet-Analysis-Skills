---
name: antsword-webshell-traffic-decrypt
description: Decode AntSword webshell request and response traffic from raw HTTP messages, Wireshark hex dumps, or decompressed response bodies. Use when AntSword PHP payloads hide commands inside POST parameters, when gzip or deflate HTTP bodies must be unpacked, when request-side output markers must be extracted, or when a captured response must be stripped down to the operator-visible command output.
---

# AntSword Webshell Traffic Decrypt

Follow the request and response as a pair. Run every command from this skill directory.

## Workflow

1. Prefer the one-shot pipeline: `scripts/decrypt_antsword.py --request-file <request> --response-file <response>`.
2. If you need the steps separately:
   - Decode the request with `scripts/decode_antsword_body.py`
   - Unpack gzip/deflate with `scripts/decode_http_gzip.py`
   - Carve the real output with `scripts/extract_antsword_response.py`
3. Read [references/workflow.md](references/workflow.md) when `asenc()` is not identity/base64 or the request layout is uncommon.

## Operating Rules

- Keep request and response artifacts together. The request usually tells you how to parse the response.
- Undo HTTP gzip or deflate before interpreting AntSword markers or payload text.
- Use the `asoutput()` markers from the PHP loader to delimit the real response body.
- If `asenc()` is not identity or base64, inspect the decoded PHP before assuming the response is plain text.
- Use the scripts in `scripts/`. Files in `antsword-traffic-decrypt/` are the original toolkit and sample captures.

## Resources

- `scripts/decrypt_antsword.py`: Decode a matching request/response pair in one pass.
- `scripts/decode_http_gzip.py`: Extract the HTTP body and decompress gzip or deflate content.
- `scripts/decode_antsword_body.py`: Decode common AntSword request bodies and summarize embedded commands.
- `scripts/extract_antsword_response.py`: Use request-side markers to carve out the real response payload.
- `antsword-traffic-decrypt/`: Original scripts plus sample request `1.txt` and gzip hex-dump response `2.txt`.
- `references/workflow.md`: End-to-end request and response workflow with sample commands.
