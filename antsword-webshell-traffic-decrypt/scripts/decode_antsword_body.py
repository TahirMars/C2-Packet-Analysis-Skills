#!/usr/bin/env python3

import argparse
import base64
import binascii
import re
import shlex
import sys
from urllib.parse import unquote_plus


POST_B64_SUBSTR_RE = re.compile(
    r"(?:(?:\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)@?)?"
    r"base64_decode\s*\(\s*substr\s*\(\s*"
    r"\$_POST\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*,\s*(\d+)\s*\)\s*\)",
    re.I,
)

ECHO_MARKER_RE = re.compile(
    r"echo\s+['\"]([^'\"]*)['\"]\s*\.\s*['\"]([^'\"]*)['\"]\s*;",
    re.I,
)

PHP_B64_LITERAL_RE = re.compile(
    r"@?base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=_-]+)['\"]\s*\)",
    re.I,
)


def extract_http_body(data):
    data = data.strip("\ufeff")
    if "\r\n\r\n" in data:
        return data.split("\r\n\r\n", 1)[1]
    if "\n\n" in data:
        return data.split("\n\n", 1)[1]
    return data.strip()


def parse_body(body):
    body = body.strip()
    if body.startswith("?"):
        body = body[1:]

    matches = list(re.finditer(r"(?:^|&)([A-Za-z0-9_]{1,100})=", body))
    params = []
    for index, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        raw_value = body[value_start:value_end]
        params.append((unquote_plus(key), unquote_plus(raw_value)))
    return params


def b64decode_relaxed(value):
    value = re.sub(r"\s+", "", value)
    if not value:
        return b""
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error:
        return base64.urlsafe_b64decode(value)


def is_mostly_text(data):
    if not data:
        return True
    printable = 0
    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1
    return printable / len(data) >= 0.85


def format_bytes(data):
    if data == b"":
        return "<empty>"
    if is_mostly_text(data):
        return data.decode("utf-8", "replace")
    return data.hex()


def find_php_payload(params):
    for key, value in params:
        if "$_POST" in value or "base64_decode" in value or "@ini_set" in value:
            return key, value
    return None, None


def looks_like_php(value):
    return "$_POST" in value or "base64_decode" in value or "@ini_set" in value or "<?php" in value


def decode_referenced_params(params, php_code):
    param_map = dict(params)
    decoded = []
    for var_name, post_name, prefix_len in POST_B64_SUBSTR_RE.findall(php_code):
        prefix_len = int(prefix_len)
        if post_name not in param_map:
            decoded.append(
                {
                    "var": var_name or "",
                    "name": post_name,
                    "prefix": prefix_len,
                    "found": False,
                    "decoded": b"",
                    "error": "parameter not found",
                }
            )
            continue

        encoded = param_map[post_name]
        try:
            decoded_value = b64decode_relaxed(encoded[prefix_len:])
            decoded.append(
                {
                    "var": var_name or "",
                    "name": post_name,
                    "prefix": prefix_len,
                    "found": True,
                    "decoded": decoded_value,
                    "error": "",
                }
            )
        except Exception as exc:
            decoded.append(
                {
                    "var": var_name or "",
                    "name": post_name,
                    "prefix": prefix_len,
                    "found": True,
                    "decoded": b"",
                    "error": str(exc),
                }
            )
    return decoded


def auto_decode_params(params, max_prefix):
    results = []
    for key, value in params:
        candidates = []
        for prefix in range(0, min(max_prefix, len(value)) + 1):
            candidate = value[prefix:]
            if not candidate:
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", candidate):
                continue
            try:
                decoded = b64decode_relaxed(candidate)
            except Exception:
                continue
            if decoded and is_mostly_text(decoded):
                candidates.append((prefix, decoded))
        if candidates:
            results.append((key, candidates))
    return results


def extract_output_markers(php_code):
    markers = [left + right for left, right in ECHO_MARKER_RE.findall(php_code)]
    if len(markers) >= 2:
        return markers[0], markers[-1]
    return None, None


def decode_php_base64_literals(php_code):
    decoded = []
    seen = set()
    for match in PHP_B64_LITERAL_RE.finditer(php_code):
        value = match.group(1)
        if value in seen:
            continue
        seen.add(value)
        try:
            decoded.append((value, b64decode_relaxed(value)))
        except Exception as exc:
            decoded.append((value, f"<decode error: {exc}>".encode()))
    return decoded


def looks_like_shell_command(data):
    if not data or not is_mostly_text(data):
        return False
    text = data.decode("utf-8", "replace").strip()
    command_hints = (
        "cd ",
        "pwd",
        "ls",
        "dir",
        "whoami",
        "route",
        "arp ",
        "ipconfig",
        "ifconfig",
        "netstat",
        "echo ",
        "cmd ",
        "/bin/sh",
        "powershell",
    )
    if ";" in text or "&&" in text or "||" in text:
        return any(hint in text for hint in command_hints)
    return text.startswith(command_hints)


def summarize_inline_commands(php_code, literals):
    commands = []
    for encoded, decoded_value in literals:
        if not looks_like_shell_command(decoded_value):
            continue

        command = decoded_value.decode("utf-8", "replace")
        shell = None
        pattern = (
            r"(?:pwn|runcmd|system|passthru|shell_exec|exec|proc_open)\s*\("
            r"(?P<expr>.{0,250}?"
            + re.escape(encoded)
            + r".{0,250}?)\)"
        )
        match = re.search(pattern, php_code, re.I | re.S)
        if match:
            expr = match.group("expr")
            if "/bin/sh" in expr and " -c " in expr:
                shell = f"/bin/sh -c {shlex.quote(command)}"
            elif "cmd" in expr and " /c " in expr.lower():
                shell = f"cmd /c {command}"

        commands.append((command, shell))
    return commands


def summarize_command(decoded):
    by_var = {item["var"]: item["decoded"] for item in decoded if item["found"] and not item["error"]}
    program = by_var.get("p")
    shell_arg = by_var.get("s")
    env = by_var.get("envstr")

    if not program and not shell_arg:
        return []

    lines = []
    if program:
        lines.append(("program", program))
    if shell_arg:
        lines.append(("shell_command", shell_arg))
    if program and shell_arg:
        rendered = program.decode("utf-8", "replace") + " -c " + repr(shell_arg.decode("utf-8", "replace"))
        lines.append(("likely_unix_exec", rendered.encode()))
    if env:
        lines.append(("env", env))
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Statically decode common AntSword/WebShell HTTP body parameters."
    )
    parser.add_argument("body", nargs="?", help="Raw HTTP body or full HTTP request. Reads stdin when omitted.")
    parser.add_argument("-f", "--file", help="Read body from file.")
    parser.add_argument(
        "--all-candidates",
        action="store_true",
        help="Also try base64 decoding every parameter with prefix lengths 0..N.",
    )
    parser.add_argument(
        "--max-prefix",
        type=int,
        default=6,
        help="Maximum prefix length for --all-candidates, default: 6.",
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    elif args.body is not None:
        data = args.body
    else:
        data = sys.stdin.read()

    body = extract_http_body(data)
    params = parse_body(body)

    if not params:
        decoded_body = unquote_plus(body)
        if looks_like_php(decoded_body):
            params = [("<raw>", decoded_body)]

    print(f"Parameters: {len(params)}")
    for key, value in params:
        print(f"- {key}: length={len(value)}")

    php_key, php_code = find_php_payload(params)
    if php_code:
        print()
        print(f"PHP payload parameter: {php_key}")
        prefix_marker, suffix_marker = extract_output_markers(php_code)
        if prefix_marker or suffix_marker:
            print(f"Output prefix marker: {prefix_marker}")
            print(f"Output suffix marker: {suffix_marker}")

        literals = decode_php_base64_literals(php_code)
        if literals:
            print()
            print("PHP base64 literals:")
            for encoded, decoded_value in literals:
                print(f"- {encoded}")
                print(f"  text: {format_bytes(decoded_value)}")
                print(f"  hex : {decoded_value.hex()}")

            inline_commands = summarize_inline_commands(php_code, literals)
            if inline_commands:
                print()
                print("Inline command summary:")
                for command, shell in inline_commands:
                    print(f"- command: {command}")
                    if shell:
                        print(f"  likely_exec: {shell}")

        decoded = decode_referenced_params(params, php_code)
        if decoded:
            print()
            print("Referenced POST parameters:")
            for item in decoded:
                label = f"${item['var']} <- " if item["var"] else ""
                print(f"- {label}{item['name']} prefix={item['prefix']}")
                if item["error"]:
                    print(f"  error: {item['error']}")
                else:
                    print(f"  text: {format_bytes(item['decoded'])}")
                    print(f"  hex : {item['decoded'].hex()}")

            command_lines = summarize_command(decoded)
            if command_lines:
                print()
                print("Command summary:")
                for label, value in command_lines:
                    print(f"- {label}: {format_bytes(value)}")
    else:
        print()
        print("PHP payload parameter: <not found>")

    if args.all_candidates:
        print()
        print("Base64 candidates:")
        for key, candidates in auto_decode_params(params, args.max_prefix):
            print(f"- {key}")
            for prefix, decoded in candidates:
                print(f"  prefix={prefix}: {format_bytes(decoded)}")


if __name__ == "__main__":
    main()
