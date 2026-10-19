#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import gzip
import re
import sys
import zlib


HEX_DUMP_RE = re.compile(
    r"^\s*(?:[0-9a-fA-F]{4,8}\s+)?((?:[0-9a-fA-F]{2}\s+){1,32})",
    re.M,
)


def read_input(path, raw):
    if path:
        mode = "rb" if raw else "r"
        kwargs = {} if raw else {"encoding": "utf-8", "errors": "replace"}
        with open(path, mode, **kwargs) as f:
            return f.read()
    data = sys.stdin.buffer.read()
    if raw:
        return data
    return data.decode("utf-8", "replace")


def parse_hex_dump(text):
    chunks = []
    for match in HEX_DUMP_RE.finditer(text):
        hex_part = match.group(1)
        chunks.extend(re.findall(r"[0-9a-fA-F]{2}", hex_part))
    if not chunks:
        raise ValueError("没有在输入中识别到 Wireshark 风格的 hex dump 字节")
    return bytes(int(item, 16) for item in chunks)


def split_http_message(data):
    for sep in (b"\r\n\r\n", b"\n\n"):
        index = data.find(sep)
        if index != -1:
            return data[:index], data[index + len(sep) :]
    return b"", data


def parse_headers(header_bytes):
    headers = {}
    lines = header_bytes.decode("iso-8859-1", "replace").splitlines()
    status_line = lines[0] if lines else ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status_line, headers


def decode_body(body, encoding):
    encoding = encoding.lower().strip()
    if encoding == "gzip" or body.startswith(b"\x1f\x8b"):
        return gzip.decompress(body)
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    if encoding in ("", "identity"):
        return body
    raise ValueError(f"暂不支持 Content-Encoding: {encoding}")


def write_output(path, data):
    if path:
        with open(path, "wb") as f:
            f.write(data)
    else:
        sys.stdout.buffer.write(data)


def main():
    parser = argparse.ArgumentParser(
        description="Decode gzip/deflate HTTP bodies from Wireshark hex dumps or raw HTTP response files."
    )
    parser.add_argument("-f", "--file", help="Input file. Default reads stdin.")
    parser.add_argument("-o", "--output", help="Write decoded body to file. Default writes to stdout.")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Treat input as raw HTTP bytes instead of Wireshark hex dump text.",
    )
    parser.add_argument(
        "--body-only",
        action="store_true",
        help="Treat input bytes as compressed body only, without HTTP headers.",
    )
    parser.add_argument(
        "--encoding",
        default="",
        help="Override content encoding, e.g. gzip or deflate.",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Print parsed metadata to stderr.",
    )
    args = parser.parse_args()

    source = read_input(args.file, args.raw)
    data = source if args.raw else parse_hex_dump(source)

    if args.body_only:
        header = b""
        body = data
        status_line = ""
        headers = {}
    else:
        header, body = split_http_message(data)
        status_line, headers = parse_headers(header)

    encoding = args.encoding or headers.get("content-encoding", "")
    decoded = decode_body(body, encoding)

    if args.info:
        print(f"status: {status_line or '<none>'}", file=sys.stderr)
        print(f"content-encoding: {encoding or '<none>'}", file=sys.stderr)
        print(f"compressed-bytes: {len(body)}", file=sys.stderr)
        print(f"decoded-bytes: {len(decoded)}", file=sys.stderr)

    write_output(args.output, decoded)


if __name__ == "__main__":
    main()
