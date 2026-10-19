#!/usr/bin/env python3

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import textwrap

try:
    from Crypto.PublicKey import RSA
except ImportError:
    RSA = None


def clean_hex(value):
    value = value.strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    return re.sub(r"[^0-9a-fA-F]", "", value)


def parse_int(value):
    return int(value, 0)


def der_len(length):
    if length < 0x80:
        return bytes([length])
    data = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(data)]) + data


def der_int(value):
    if value == 0:
        data = b"\x00"
    else:
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return b"\x02" + der_len(len(data)) + data


def der_sequence(*items):
    body = b"".join(items)
    return b"\x30" + der_len(len(body)) + body


def der_to_pem(der, label):
    encoded = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(encoded, 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def build_private_key(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)

    if RSA is not None:
        rsa_key = RSA.construct((n, e, d, p, q))
        der = rsa_key.export_key("DER")
        pem = rsa_key.export_key("PEM").decode("ascii")
    else:
        der = der_sequence(
            der_int(0),
            der_int(n),
            der_int(e),
            der_int(d),
            der_int(p),
            der_int(q),
            der_int(dp),
            der_int(dq),
            der_int(qinv),
        )
        pem = der_to_pem(der, "RSA PRIVATE KEY")

    return {
        "n": n,
        "e": e,
        "d": d,
        "p": p,
        "q": q,
        "der": der,
        "pem": pem,
    }


def normalize_public_key_hex(value):
    return binascii.unhexlify(clean_hex(str(value))).rstrip(b"\x00").hex()


def parse_public_key(hex_key):
    if RSA is None:
        raise RuntimeError("pycryptodome is required for public key parsing")
    key_bytes = binascii.unhexlify(normalize_public_key_hex(hex_key))
    rsa_key = RSA.import_key(key_bytes)
    return {
        "n": rsa_key.n,
        "e": rsa_key.e,
        "pem": rsa_key.publickey().export_key("PEM").decode("ascii"),
    }


def read_private_numbers_from_pem(path):
    if RSA is None:
        raise RuntimeError("pycryptodome is required to import PEM private keys")
    with open(path, "rb") as f:
        key = RSA.import_key(f.read())
    return key.n, key.e, key.d


def save_private_key(path, pem):
    with open(path, "w", encoding="ascii") as f:
        f.write(pem)


def decode_metadata_blob(value):
    stripped = re.sub(r"\s+", "", value)
    if not stripped:
        raise ValueError("metadata value is empty")

    hex_value = clean_hex(stripped)
    if stripped.lower().startswith("0x") or (
        len(hex_value) == len(stripped) and len(hex_value) % 2 == 0
    ):
        return binascii.unhexlify(hex_value), "hex"

    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.b64decode(padded, validate=True), "base64"
    except binascii.Error:
        return base64.urlsafe_b64decode(padded), "base64url"


def pkcs1_v1_5_decrypt(ciphertext, n, d):
    key_len = (n.bit_length() + 7) // 8
    if len(ciphertext) != key_len:
        raise ValueError(
            f"ciphertext length {len(ciphertext)} does not match RSA modulus length {key_len}"
        )

    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    block = m.to_bytes(key_len, "big")

    if not block.startswith(b"\x00\x02"):
        raise ValueError("decrypted RSA block is not PKCS#1 v1.5 padded")

    separator = block.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("invalid PKCS#1 v1.5 padding layout")

    return block[separator + 1 :], block


def extract_keys(plain):
    if plain[:4] != b"\x00\x00\xbe\xef":
        raise ValueError(f"unexpected metadata header: {plain[:4].hex()}")
    if len(plain) < 24:
        raise ValueError(f"metadata block too short: {len(plain)}")

    raw_key = plain[8:24]
    digest = hashlib.sha256(raw_key).digest()
    return {
        "raw_key": raw_key,
        "aes_key": digest[:16],
        "hmac_key": digest[16:],
        "sha256": digest,
    }


def hexdump(data, width=16):
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_text = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_bytes:<{width * 3}} {ascii_text}")
    return "\n".join(lines)


def load_1768_config(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, dict) and "config" in data:
        config = data["config"]
    else:
        config = data

    if isinstance(config, list):
        if not config:
            raise ValueError("1768 JSON config list is empty")
        config = config[0]
    if not isinstance(config, dict):
        raise ValueError("1768 JSON does not contain a config object")
    return config


def config_entries(config):
    entries = []
    for value in config.values():
        if isinstance(value, dict) and value.get("id"):
            entries.append(value)
    return entries


def extract_public_key_hex(config):
    for entry in config_entries(config):
        if entry.get("id") == "publickey" and entry.get("rawvalue"):
            return normalize_public_key_hex(entry["rawvalue"])
    for key in ("7", 7):
        value = config.get(key)
        if isinstance(value, dict) and value.get("rawvalue"):
            return normalize_public_key_hex(value["rawvalue"])
    raise ValueError("publickey not found in 1768 JSON")


def cmd_public_info(args):
    public_key_hex = args.public_key_hex
    if args.beacon_json:
        public_key_hex = extract_public_key_hex(load_1768_config(args.beacon_json))
        print(f"public_key_hex: {public_key_hex}")
    info = parse_public_key(public_key_hex)
    print(f"modulus_n_dec: {info['n']}")
    print(f"modulus_n_hex: {info['n']:x}")
    print(f"exponent_e: {info['e']}")
    print("public_key_pem:")
    print(info["pem"], end="")


def cmd_config_summary(args):
    config = load_1768_config(args.beacon_json)
    wanted = (
        "publickey",
        "Malleable_C2_Instructions",
        "http_get_header",
        "http_post_header",
        "server,get-uri",
        "post-uri",
        "useragent",
        "get-verb",
        "post-verb",
        "UsesCookies",
        "CryptoScheme",
        "license-id",
    )
    printed = set()
    for entry in config_entries(config):
        name = entry.get("id")
        if name not in wanted or name in printed:
            continue
        printed.add(name)
        rawvalue = entry.get("rawvalue")
        info = entry.get("info") or ""
        print(f"{name}:")
        if name == "publickey" and rawvalue:
            print(f"  hex: {normalize_public_key_hex(rawvalue)}")
            continue
        if info:
            if name in ("http_get_header", "http_post_header", "Malleable_C2_Instructions"):
                lines = [line.strip() for line in str(info).split(";") if line.strip()]
            else:
                lines = [str(info)]
            for line in lines:
                print(f"  {line}")
        elif rawvalue not in (None, ""):
            print(f"  {rawvalue}")

    missing = [name for name in wanted if name not in printed]
    if missing:
        print("missing:")
        for name in missing:
            print(f"  {name}")


def cmd_private_key(args):
    p = parse_int(args.p)
    q = parse_int(args.q)
    e = parse_int(args.e)
    private_key = build_private_key(p, q, e)

    if args.out:
        save_private_key(args.out, private_key["pem"])
        print(f"private_key_file: {args.out}")

    print(f"modulus_n_dec: {private_key['n']}")
    print(f"modulus_n_hex: {private_key['n']:x}")
    print(f"exponent_e: {private_key['e']}")
    print("private_key_pem:")
    print(private_key["pem"], end="")


def cmd_metadata(args):
    ciphertext, encoding = decode_metadata_blob(args.metadata)

    if args.private_key_file:
        n, e, d = read_private_numbers_from_pem(args.private_key_file)
        private_key = None
    else:
        p = parse_int(args.p)
        q = parse_int(args.q)
        e = parse_int(args.e)
        private_key = build_private_key(p, q, e)
        n = private_key["n"]
        d = private_key["d"]
        if args.out_key:
            save_private_key(args.out_key, private_key["pem"])
            print(f"private_key_file: {args.out_key}")

    plain, block = pkcs1_v1_5_decrypt(ciphertext, n, d)
    keys = extract_keys(plain)

    print(f"metadata_encoding: {encoding}")
    print(f"metadata_ciphertext_hex: {ciphertext.hex()}")
    print(f"raw_key: {keys['raw_key'].hex()}")
    print(f"aes_key: {keys['aes_key'].hex()}")
    print(f"hmac_key: {keys['hmac_key'].hex()}")
    print(f"sha256_raw_key: {keys['sha256'].hex()}")
    print()
    print(f"metadata_plain_hex: {plain.hex()}")
    print("metadata_plain_hexdump:")
    print(hexdump(plain))
    print()
    print(f"rsa_block_hex: {block.hex()}")

    if args.print_parse_hint:
        print()
        print("cs_parse_hint:")
        print(
            "python cs-parse-http-traffic/cs-parse-http-traffic.py "
            f"-r {keys['raw_key'].hex()} -Y \"http\" <capture.pcapng> -o traffic.txt"
        )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Recover Cobalt Strike RSA and session keys from Beacon artifacts."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    public_info = subparsers.add_parser(
        "public-info",
        help="Parse a Beacon DER public key and print modulus, exponent, and PEM.",
    )
    public_info.add_argument("--public-key-hex", help="DER public key in hex.")
    public_info.add_argument(
        "--1768-json",
        dest="beacon_json",
        help="1768.py JSON output file containing the Beacon config.",
    )
    public_info.set_defaults(func=cmd_public_info)

    config_summary = subparsers.add_parser(
        "config-summary",
        help="Print C2 fields needed for metadata and HTTP decrypt from 1768.py JSON.",
    )
    config_summary.add_argument(
        "--1768-json",
        dest="beacon_json",
        required=True,
        help="1768.py JSON output file containing the Beacon config.",
    )
    config_summary.set_defaults(func=cmd_config_summary)

    private_key = subparsers.add_parser(
        "private-key",
        help="Rebuild a private key from p, q, and e.",
    )
    private_key.add_argument("--p", required=True, help="Prime p in decimal or 0x-prefixed hex.")
    private_key.add_argument("--q", required=True, help="Prime q in decimal or 0x-prefixed hex.")
    private_key.add_argument("--e", default="65537", help="Exponent e, default 65537.")
    private_key.add_argument("--out", help="Optional PEM output file.")
    private_key.set_defaults(func=cmd_private_key)

    metadata = subparsers.add_parser(
        "metadata",
        help="Decrypt Beacon metadata and print raw, AES, and HMAC keys.",
    )
    metadata.add_argument("--metadata", required=True, help="Encrypted metadata as hex or base64.")
    metadata.add_argument("--private-key-file", help="Existing PEM private key.")
    metadata.add_argument("--p", help="Prime p when rebuilding the private key.")
    metadata.add_argument("--q", help="Prime q when rebuilding the private key.")
    metadata.add_argument("--e", default="65537", help="Exponent e, default 65537.")
    metadata.add_argument("--out-key", help="Write the rebuilt private key to this PEM file.")
    metadata.add_argument(
        "--print-parse-hint",
        action="store_true",
        help="Print a follow-up cs-parse-http-traffic.py command template.",
    )
    metadata.set_defaults(func=cmd_metadata)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "public-info":
        if not args.public_key_hex and not args.beacon_json:
            parser.error("public-info requires --public-key-hex or --1768-json")
    if args.command == "metadata":
        if not args.private_key_file and not (args.p and args.q):
            parser.error("metadata requires --private-key-file or both --p and --q")

    try:
        args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
