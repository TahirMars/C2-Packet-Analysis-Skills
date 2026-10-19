#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import hashlib
import textwrap

try:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:
    PKCS1_v1_5 = None
    RSA = None


DEFAULT_P = 7605291443685150594150190909345113655196508809219162555499789316232908573154196070425269090153291952292016936024761413150455793038505322748933150548026527
DEFAULT_Q = 7605291443685150594150190909345113655196508809219162555499789316232908573154196070425269090153291952292016936024761413150455793038505322748933150548026221
DEFAULT_E = 65537
DEFAULT_ENCODE_DATA = (
    "SLHAIOj8/1icVtP6fImtJz6B6wR0t/XwLg1G0Y3AxoxnseBfPONxoyjAWCCOH84I"
    "JULnCZZrO7cIRxJPS2PtmDD4MvD8/PIpoW8Gj8536vhwd+tyXjNKyLNyNYcj+JgO"
    "4N5FTnKtkONgv7KnsMjJC3E0eI0ctqmZll8SrXLUS9k="
)


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


def build_rsa_private_key(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    if RSA is not None:
        rsa_key = RSA.construct((n, e, d))
        der = rsa_key.export_key("DER")
        return {
            "n": n,
            "e": e,
            "d": d,
            "der": der,
            "pem": rsa_key.export_key("PEM").decode("ascii"),
            "backend": "pycryptodome",
        }

    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)
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
    return {
        "n": n,
        "e": e,
        "d": d,
        "der": der,
        "pem": der_to_pem(der, "RSA PRIVATE KEY"),
        "backend": "builtin",
    }


def der_to_pem(der, label):
    encoded = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(encoded, 64))
    return f"-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----\n"


def save_private_key(pem, path):
    with open(path, "w", encoding="ascii") as f:
        f.write(pem)


def pkcs1_v1_5_decrypt(encoded_data, n, d):
    encrypted = base64.b64decode(encoded_data)
    key_len = (n.bit_length() + 7) // 8
    if len(encrypted) != key_len:
        raise ValueError(
            f"密文长度({len(encrypted)})与RSA模数长度({key_len})不一致"
        )

    c = int.from_bytes(encrypted, "big")
    m = pow(c, d, n)
    encoded_message = m.to_bytes(key_len, "big")

    if not encoded_message.startswith(b"\x00\x02"):
        raise ValueError("RSA解密结果不是PKCS#1 v1.5加密块")

    sep = encoded_message.find(b"\x00", 2)
    if sep < 10:
        raise ValueError("PKCS#1 v1.5填充格式异常")

    return encoded_message[sep + 1 :], encoded_message


def decrypt_encode_data(encoded_data, private_key):
    if PKCS1_v1_5 is not None and RSA is not None:
        rsa_key = RSA.import_key(private_key["pem"].encode("ascii"))
        cipher = PKCS1_v1_5.new(rsa_key)
        sentinel = object()
        plain = cipher.decrypt(base64.b64decode(encoded_data), sentinel)
        if plain is sentinel:
            raise ValueError("RSA PKCS#1 v1.5解密失败")
        rsa_block = None
        return plain, rsa_block

    return pkcs1_v1_5_decrypt(encoded_data, private_key["n"], private_key["d"])


def hexdump(data, width=16):
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_bytes:<{width * 3}} {ascii_text}")
    return "\n".join(lines)


def extract_keys(plain):
    if plain[:4] != b"\x00\x00\xbe\xef":
        raise ValueError(f"解密明文魔术头不匹配: {plain[:4].hex()}")
    if len(plain) < 24:
        raise ValueError(f"解密明文长度过短: {len(plain)}")

    raw_aes_key = plain[8:24]
    aes_hash = hashlib.sha256(raw_aes_key).digest()
    aes_key = aes_hash[:16]
    mac_key = aes_hash[16:]
    return raw_aes_key, aes_hash, aes_key, mac_key


def parse_args():
    parser = argparse.ArgumentParser(
        description="通过RSA p/q和base64 encode_data恢复AES相关密钥并输出RSA私钥。"
    )
    parser.add_argument("--p", type=int, default=DEFAULT_P, help="RSA素数p")
    parser.add_argument("--q", type=int, default=DEFAULT_Q, help="RSA素数q")
    parser.add_argument("--e", type=int, default=DEFAULT_E, help="RSA公钥指数")
    parser.add_argument(
        "--encode-data",
        default=DEFAULT_ENCODE_DATA,
        help="base64编码的RSA加密数据",
    )
    parser.add_argument(
        "--out-key",
        default="id_rsa",
        help="RSA私钥PEM输出路径，默认: id_rsa",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    private_key = build_rsa_private_key(args.p, args.q, args.e)
    save_private_key(private_key["pem"], args.out_key)
    print(f"Backend: {private_key['backend']}")
    print(f"RSA private key file: {args.out_key}")
    print(f"RSA private key PEM HEX: {private_key['pem'].encode('ascii').hex()}")
    print(f"RSA private key DER HEX: {private_key['der'].hex()}")
    print()
    
    plain, rsa_block = decrypt_encode_data(args.encode_data, private_key)
    raw_aes_key, aes_hash, aes_key, mac_key = extract_keys(plain)
    print(f"RAW AES key: {raw_aes_key.hex()}")
    print(f"AES key hash SHA256: {aes_hash.hex()}")
    print(f"AES key: {aes_key.hex()}")
    print(f"MAC/HMAC key: {mac_key.hex()}")
    print()
    print(f"Decrypted encode_data HEX: {plain.hex()}")
    print("Decrypted encode_data hexdump:")
    print(hexdump(plain))
    if rsa_block is not None:
        print()
        print(f"RSA decrypted block HEX: {rsa_block.hex()}")


if __name__ == "__main__":
    main()
