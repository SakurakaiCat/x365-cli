<div align="center">
  <img src="../assets/open-x365.svg" alt="Open X365" width="460">
</div>

# x365-cli

A minimal Go client: account login and
export of `x365://` node links — no GUI required.

## Protocol summary

| Step | Detail |
| --- | --- |
| `x-sig` header | device-info JSON, RSA-2048 PKCS#1 v1.5 encrypted (public key) in 245-byte chunks, concatenated, base64 |
| login | `POST /v1/auth/login` `{email, password, reg:false}` + `x-did`/`x-sig` → `{access_token}` (JWT) |
| config | `GET /v1/app?flag=wassvpn` + `authorization: <JWT>` → JSON with `proxy` field |
| decode | `base64(proxy)` → RSA-2048 private-decrypt each 256-byte block → zlib → YAML containing `x365://` links |

Two PEM keys are shipped in this repository; they are required to build
`x-sig` and to decrypt the `proxy` config blob.

## Build

```sh
# from the repository root
go build -o x365 ./cmd/x365-cli
```

No third-party dependencies.

## Usage

```sh
# print a fresh JWT
./x365 login  -email user@example.com -password 'secret'

# list node links
./x365 nodes  -email user@example.com -password 'secret'

# dump the full decrypted YAML config
./x365 config -email user@example.com -password 'secret'
```

Optional flags:

- `-did <uuid>` — stable device id (default: random per run, or `$X365_DID`; a fixed did keeps the device slot stable server-side)
- `-api <url>` — override API base (defaults to the CloudFront endpoint)

## Notes

- The `x-sig` payload contains no timestamp or nonce; a signature is reusable
  per device.
- Successfully tested end-to-end: fresh login → 30 `x365://` nodes extracted.
