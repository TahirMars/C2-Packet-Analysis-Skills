# AntSword workflow

Run every command from the skill directory (`antsword-webshell-traffic-decrypt/`).

## Inputs

- The HTTP request that delivered the AntSword payload.
- The matching HTTP response.
- If the response is compressed, either the raw HTTP message or a Wireshark hex dump of it.

## Preferred path: one-shot pipeline

```powershell
python scripts/decrypt_antsword.py --request-file <request.txt> --response-file <response.txt>
```

Use `--raw-response` when the response file already contains raw HTTP bytes instead of hex-dump text.

Use `--response-already-decoded` when the response body is already decompressed.

Use `--output payload.bin` to save the carved payload.

The pipeline prints:

- request-side PHP parameter, markers, and command summary
- gzip/deflate transport metadata
- the operator-visible response payload

## Step-by-step path

### Step 1: decode the request

Start from the request because it usually contains:

- the PHP loader body
- output prefix and suffix markers
- the parameter names that carry operator commands
- any response encoder implemented by `asenc()`

```powershell
python scripts/decode_antsword_body.py --file <request.txt>
```

Review:

- `PHP payload parameter`
- `Output prefix marker`
- `Output suffix marker`
- `Referenced POST parameters`
- `Command summary`

### Step 2: unpack the HTTP response if needed

If the response is a raw HTTP message or a Wireshark hex dump and `Content-Encoding` is `gzip` or `deflate`, decode it first.

```powershell
python scripts/decode_http_gzip.py --file <response.txt> --output response.bin --info
```

Use `--raw` when the input file already contains raw HTTP bytes instead of hex-dump text.

### Step 3: extract the real AntSword output

```powershell
python scripts/extract_antsword_response.py --request-file <request.txt> --response-file response.bin --body-only
```

The extractor:

- locates the prefix and suffix markers from the request automatically
- strips those markers from the response
- optionally base64-decodes the extracted payload when it looks encoded

If you already know the markers, pass them directly:

```powershell
python scripts/extract_antsword_response.py --response-file response.bin --prefix f24b354ebfb --suffix 3c9386cd19a --body-only
```

## Common variants

- `asenc($out) { return $out; }`
  The output is plain text between the markers.
- `asenc($out) { return base64_encode($out); }`
  The output between the markers must be base64-decoded.
- Custom XOR or charset encoders
  Inspect the PHP body and reproduce that transform explicitly. Do not guess from the response alone.

## Bundled samples

The original toolkit and captures live in `antsword-traffic-decrypt/`:

```powershell
python scripts/decrypt_antsword.py --request-file antsword-traffic-decrypt/1.txt --response-file antsword-traffic-decrypt/2.txt
```

Equivalent step-by-step commands:

```powershell
python scripts/decode_antsword_body.py --file antsword-traffic-decrypt/1.txt
python scripts/decode_http_gzip.py --file antsword-traffic-decrypt/2.txt --output response.bin --info
python scripts/extract_antsword_response.py --request-file antsword-traffic-decrypt/1.txt --response-file response.bin --body-only
```

Use `scripts/` for analysis. `antsword-traffic-decrypt/http_gzip_decode.py` and `antsword-traffic-decrypt/antsword_body_decode.py` are the original helpers and are superseded by the skill scripts.
