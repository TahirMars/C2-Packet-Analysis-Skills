#!/usr/bin/env python3

import argparse
import base64
import binascii
import re
import sys
from urllib.parse import unquote_plus


ECHO_MARKER_RE = re.compile(
    r"echo\s+['\"]([^'\"]*)['\"]\s*\.\s*['\"]([^'\"]*)['\"]\s*;",
    re.I,
)

ASENC_IDENTITY_RE = re.compile(
    r"function\s+asenc\s*\(\s*\$out\s*\)\s*\{\s*return\s+\$out\s*;\s*\}",
    re.I | re.S,
)

ASENC_BASE64_RE = re.compile(
    r"function\s+asenc\s*\(\s*\$out\s*\)\s*\{\s*return\s+@?base64_encode\s*\(\s*\$out\s*\)\s*;\s*\}",
    re.I | re.S,
)


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def split_http_message(data):
    for sep in (b"\r\n\r\n", b"\n\n"):
        index = data.find(sep)
        if index != -1:
            return data[:index], data[index + len(sep) :]
    return b"", data


def extract_http_body_text(text):
    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)[1]
    if "\n\n" in text:
        return text.split("\n\n", 1)[1]
    return text


def parse_form_body(body):
    body = body.strip()
    matches = list(re.finditer(r"(?:^|&)([A-Za-z0-9_]{1,100})=", body))
    params = []
    for index, match in enumerate(matches):
        key = unquote_plus(match.group(1))
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        value = unquote_plus(body[value_start:value_end])
        params.append((key, value))
    return params


def find_php_payload(request_text):
    body = extract_http_body_text(request_text)
    params = parse_form_body(body)
    for _, value in params:
        if "$_POST" in value or "base64_decode" in value or "@ini_set" in value:
            return value
    decoded_body = unquote_plus(body)
    if "$_POST" in decoded_body or "base64_decode" in decoded_body or "@ini_set" in decoded_body:
        return decoded_body
    return None


def extract_markers_from_php(php_code):
    markers = [left + right for left, right in ECHO_MARKER_RE.findall(php_code)]
    if len(markers) >= 2:
        return markers[0], markers[-1]
    return None, None


def detect_encoder_from_php(php_code):
    if ASENC_IDENTITY_RE.search(php_code):
        return "identity"
    if ASENC_BASE64_RE.search(php_code):
        return "base64"
    return "unknown"


def extract_payload(body, prefix, suffix):
    if not prefix and not suffix:
        return body

    prefix_bytes = prefix.encode("utf-8") if prefix else b""
    suffix_bytes = suffix.encode("utf-8") if suffix else b""

    start = 0
    end = len(body)

    if prefix_bytes:
        start = body.find(prefix_bytes)
        if start == -1:
            raise ValueError("response prefix marker not found")
        start += len(prefix_bytes)

    if suffix_bytes:
        end = body.rfind(suffix_bytes)
        if end == -1:
            raise ValueError("response suffix marker not found")

    if end < start:
        raise ValueError("response markers overlap or are reversed")

    return body[start:end]


def maybe_base64_decode(data, mode, encoder):
    if mode == "never":
        return data, False, "disabled"
    if mode == "auto" and encoder == "identity":
        return data, False, "identity"
    if mode == "auto" and encoder not in ("unknown", "base64"):
        return data, False, encoder

    stripped = re.sub(rb"\s+", b"", data)
    if not stripped:
        return data, False, "empty"
    if mode == "auto" and encoder == "base64":
        padded = stripped + b"=" * (-len(stripped) % 4)
        try:
            return base64.b64decode(padded, validate=True), True, "base64"
        except binascii.Error:
            return base64.urlsafe_b64decode(padded), True, "base64url"
    if not re.fullmatch(rb"[A-Za-z0-9+/=_-]+", stripped):
        return data, False, "not-base64-looking"

    padded = stripped + b"=" * (-len(stripped) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
        return decoded, True, "base64"
    except binascii.Error:
        try:
            decoded = base64.urlsafe_b64decode(padded)
            return decoded, True, "base64url"
        except binascii.Error:
            if mode == "always":
                raise ValueError("forced base64 decode failed")
            return data, False, "decode-failed"


def write_output(path, data):
    if path:
        with open(path, "wb") as f:
            f.write(data)
    else:
        sys.stdout.buffer.write(data)


def main():
    parser = argparse.ArgumentParser(
        description="Extract the real AntSword response body using request-side markers."
    )
    parser.add_argument("--response-file", required=True, help="Decoded response file to parse.")
    parser.add_argument("--request-file", help="Matching request file used to auto-extract markers.")
    parser.add_argument("--prefix", help="Explicit response prefix marker.")
    parser.add_argument("--suffix", help="Explicit response suffix marker.")
    parser.add_argument(
        "--decode-base64",
        choices=("auto", "never", "always"),
        default="auto",
        help="Whether to base64-decode the extracted response payload.",
    )
    parser.add_argument("--output", help="Optional output file. Default writes bytes to stdout.")
    parser.add_argument(
        "--body-only",
        action="store_true",
        help="Treat the response file as body bytes only, without HTTP headers.",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Print marker and decode decisions to stderr.",
    )
    args = parser.parse_args()

    prefix = args.prefix
    suffix = args.suffix
    encoder = "unknown"

    if args.request_file and (prefix is None or suffix is None):
        php_code = find_php_payload(read_text(args.request_file))
        if php_code:
            auto_prefix, auto_suffix = extract_markers_from_php(php_code)
            prefix = prefix or auto_prefix
            suffix = suffix or auto_suffix
            encoder = detect_encoder_from_php(php_code)

    response = read_bytes(args.response_file)
    if args.body_only:
        body = response
    else:
        _, body = split_http_message(response)

    extracted = extract_payload(body, prefix, suffix)
    decoded, changed, decode_mode = maybe_base64_decode(extracted, args.decode_base64, encoder)

    if args.info:
        print(f"prefix: {prefix or '<none>'}", file=sys.stderr)
        print(f"suffix: {suffix or '<none>'}", file=sys.stderr)
        print(f"encoder: {encoder}", file=sys.stderr)
        print(f"extracted-bytes: {len(extracted)}", file=sys.stderr)
        print(f"base64-decoded: {'yes' if changed else 'no'} ({decode_mode})", file=sys.stderr)

    write_output(args.output, decoded)


if __name__ == "__main__":
    main()
