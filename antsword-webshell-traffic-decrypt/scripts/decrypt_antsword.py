#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent


def emit(text=""):
    print(text, flush=True)


def is_mostly_text(data):
    if not data:
        return True
    printable = 0
    for byte in data:
        if byte in (9, 10, 13) or 32 <= byte <= 126:
            printable += 1
    return printable / len(data) >= 0.85


def run_script(name, args, capture_stdout=False):
    command = [sys.executable, str(HERE / name), *args]
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE if capture_stdout else None,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    if capture_stdout:
        return completed.stdout
    return b""


def main():
    parser = argparse.ArgumentParser(
        description="Decode a matching AntSword request/response pair."
    )
    parser.add_argument("--request-file", required=True, help="Captured HTTP request.")
    parser.add_argument("--response-file", required=True, help="Captured HTTP response.")
    parser.add_argument(
        "--raw-response",
        action="store_true",
        help="Treat the response file as raw HTTP bytes instead of a hex dump.",
    )
    parser.add_argument(
        "--response-already-decoded",
        action="store_true",
        help="Skip gzip/deflate decoding; the response file is already a body.",
    )
    parser.add_argument("--output", help="Write the extracted payload bytes to this file.")
    args = parser.parse_args()

    emit("=== Request ===")
    run_script("decode_antsword_body.py", ["--file", args.request_file])

    decoded_path = args.response_file
    tmp_path = None
    if not args.response_already_decoded:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.close()
        tmp_path = Path(tmp.name)
        decoded_path = str(tmp_path)
        gzip_args = ["--file", args.response_file, "--output", decoded_path, "--info"]
        if args.raw_response:
            gzip_args.append("--raw")
        emit()
        emit("=== Response transport ===")
        run_script("decode_http_gzip.py", gzip_args)

    extract_args = [
        "--request-file",
        args.request_file,
        "--response-file",
        decoded_path,
        "--body-only",
        "--info",
    ]
    emit()
    emit("=== Response extract ===")
    try:
        payload = run_script("extract_antsword_response.py", extract_args, capture_stdout=True)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    if args.output:
        Path(args.output).write_bytes(payload)

    emit()
    emit("=== Extracted payload ===")
    if is_mostly_text(payload):
        text = payload.decode("utf-8", "replace")
        if text and not text.endswith("\n"):
            text += "\n"
        emit(text.rstrip("\n"))
    else:
        emit(f"<binary {len(payload)} bytes>")
        emit(payload.hex())
    if args.output:
        emit(f"payload_file: {args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
