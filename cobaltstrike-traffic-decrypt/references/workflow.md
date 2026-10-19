# Cobalt Strike workflow

Run every command from the skill directory (`cobaltstrike-traffic-decrypt/`).

## Inputs

- A Beacon sample, stage, or memory dump.
- A PCAP/PCAPNG that contains the Beacon HTTP session.
- Encrypted metadata from a cookie or similar HTTP field.
- Either a leaked private key or a weak public modulus that can be factored.

## Step 1: extract the Beacon config

```powershell
python cs-1768/1768.py -J <beacon-or-stage.bin> > beacon.json
python scripts/recover_cs_keys.py config-summary --1768-json beacon.json
```

Pull at least these fields:

- `publickey`
- `Malleable_C2_Instructions`
- `http_get_header`
- `http_post_header`
- `server,get-uri`
- `post-uri`

The `publickey` field is a DER-encoded RSA public key and usually starts with `3081...`.

## Step 2: convert the public key

```powershell
python scripts/recover_cs_keys.py public-info --1768-json beacon.json
```

Or pass the hex key directly:

```powershell
python scripts/recover_cs_keys.py public-info --public-key-hex <publickey-hex>
```

Keep the decimal modulus if you plan to factor it.

## Step 3: recover the private key

Choose one path.

### Known private key

`cs-decrypt-metadata.py` can use:

- `-p` with a hex private key
- `-f` with a `.cobaltstrike.beacon.keys` file
- no key argument, which tries known keys from `cs-1768/1768.json`

```powershell
python cs-decrypt-metadata/cs-decrypt-metadata.py -f cs-decrypt-metadata/.cobaltstrike.beacon <metadata-value>
python cs-decrypt-metadata/cs-decrypt-metadata.py <metadata-value>
```

If this already prints `Raw key`, skip factorization and jump to step 5.

### Weak RSA modulus

This only works when the Beacon uses a weak RSA modulus or the primes are already known.

```powershell
cs-rsa/yafu-windows-generic.exe "factor(<modulus-n-decimal>)"
```

On Linux:

```bash
./cs-rsa/yafu-linux-generic "factor(<modulus-n-decimal>)"
```

YAFU reference: `https://github.com/bbuhrow/yafu`

Feed recovered `p` and `q` into the bundled wrapper:

```powershell
python scripts/recover_cs_keys.py private-key --p <p> --q <q> --out id_rsa
```

Do not use `cs-rsa/public_key2pem.py`, `cs-rsa/get_rsa_private_key.py`, or `cs-rsa/decrypt_from_pq.py` unless you are comparing against the original helpers. Those files contain sample-specific defaults.

## Step 4: reverse the cookie transform and decrypt metadata

The metadata cookie is often wrapped by the malleable C2 profile. Reverse the transform until the value becomes the raw encrypted metadata blob:

- Remove static prefixes or suffixes.
- Undo base64 or base64url encoding.
- Undo any extra xor or prepend operations described by the input transform.

If you already have the metadata as base64, base64url, or hex:

```powershell
python scripts/recover_cs_keys.py metadata --p <p> --q <q> --metadata <metadata-value>
```

Or with an existing PEM:

```powershell
python scripts/recover_cs_keys.py metadata --private-key-file id_rsa --metadata <metadata-value>
```

The wrapper prints:

- `raw_key`
- `aes_key`
- `hmac_key`
- the decrypted metadata block in hex and hexdump form

Add `--print-parse-hint` when you want a follow-up `cs-parse-http-traffic.py` command.

Save the reconstructed private key while decrypting:

```powershell
python scripts/recover_cs_keys.py metadata --p <p> --q <q> --metadata <metadata-value> --out-key id_rsa
```

## Step 5: decrypt the full HTTP stream

Once `raw_key` is known:

```powershell
python cs-parse-http-traffic/cs-parse-http-traffic.py -r <raw_key_hex> -Y "http" <capture.pcapng> -o traffic.txt
```

If you prefer the derived keys:

```powershell
python cs-parse-http-traffic/cs-parse-http-traffic.py -k <hmac_key_hex>:<aes_key_hex> -Y "http" <capture.pcapng> -o traffic.txt
```

`cs-parse-http-traffic.py` also accepts transform instructions with `-t` when the HTTP body needs the same malleable undo logic that was used for the metadata cookie.

## Bundled samples

- `cs-1768/dump.bin` and `cs-1768/stage(CeKi).bin`: Beacon/stage samples for `1768.py`
- `cs-parse-http-traffic/demo.pcapng`: HTTP session sample for traffic decrypt
- `cs-decrypt-metadata/.cobaltstrike.beacon`: example Java keystore-style private key file

## Bundled original tools

| Path | Role |
|------|------|
| `cs-1768/1768.py` | Beacon config extractor |
| `cs-1768/1768.json` | License and known-key lookup data |
| `cs-decrypt-metadata/cs-decrypt-metadata.py` | Metadata decryptor for known/leaked keys |
| `cs-parse-http-traffic/cs-parse-http-traffic.py` | HTTP session decryptor |
| `cs-rsa/yafu-windows-generic.exe` | Windows RSA factorization |
| `cs-rsa/yafu-linux-generic` | Linux RSA factorization |
| `cs-rsa/*.py` | Original one-off RSA helpers; superseded by `scripts/recover_cs_keys.py` |
