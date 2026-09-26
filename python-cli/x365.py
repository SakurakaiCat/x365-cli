#!/usr/bin/env python3
"""x365-cli: account login, fetch nodes, emit x365:// links.

Protocol:
  x-sig  = base64( concat over 245B chunks of RSA-2048/PKCS1v15 public-encrypt(device_json) )
  login  = POST {api}/v1/auth/login  {email,password,reg:false} -> {access_token}
  config = GET  {api}/v1/app?flag=wassvpn  (authorization: <jwt>)  -> {proxy, servers, ...}
  proxy  = base64( RSA-2048 blocks ) ; private-decrypt per 256B block, concat, zlib-decompress
           -> YAML containing x365:// node links (VLESS-Reality style)
"""
import argparse, base64, json, os, platform, re, sys, zlib
import urllib.request, urllib.error

API = "https://d2hh0svl8tdgyk.cloudfront.net"
APP_VERSION = "26.7.17"
CONFIG_VERSION = "25.11.20"
CORE_VERSION = "26.1.30"

_HERE = os.path.dirname(os.path.abspath(__file__))
_PUBKEY_PATH = os.path.join(_HERE, "server_pubkey.pem")
_PRIVKEY_PATH = os.path.join(_HERE, "..", "cmd", "x365-cli", "rsa_private_key.pem")


def _http(method, url, body=None, headers=None, timeout=20):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _egress_ip():
    for u in ("https://ifconfig.me", "https://api.ipify.org"):
        try:
            s, b = _http("GET", u, timeout=8)
            if s == 200:
                return b.decode().strip()
        except Exception:
            pass
    return "0.0.0.0"


def _uuid_new():
    return str(__import__('uuid').uuid4())


def _chunk(s, n):
    return [s[i:i + n] for i in range(0, len(s), n)]


def make_xsig(did, pubkey_pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    pub = serialization.load_pem_public_key(pubkey_pem)
    payload = {
        "app_name": "365VPN",
        "device_name": platform.node() or "linux",
        "fit": 0,
        "os": "linux" if sys.platform.startswith("linux") else ("darwin" if sys.platform == "darwin" else "windows"),
        "os_version": platform.release(),
        "app_version": APP_VERSION,
        "os_arch": "amd64",
        "client_ip": _egress_ip(),
        "api": API,
        "proxy": False,
        "did": did,
        "dns": "tls://223.5.5.5",
        "config_version": CONFIG_VERSION,
        "core_version": CORE_VERSION,
        "screen_width": "0",
        "screen_height": "0",
        "language": "en",
        "fp": "",
        "fcm_token": "",
        "build_id": "",
        "is_emulator": False,
        "build_number": "",
        "package_name": "",
    }
    blob = json.dumps(payload, separators=(",", ":")).encode()
    enc = b"".join(pub.encrypt(c, padding.PKCS1v15()) for c in _chunk(blob, 245))
    return base64.b64encode(enc).decode()


class Client:
    def __init__(self, did=None, api=API):
        self.api = api
        self.did = did or _uuid_new()
        self._pub = open(_PUBKEY_PATH, "rb").read()
        self.token = None

    def _headers(self, extra=None):
        h = {
            "user-agent": f"365VPN {APP_VERSION}",
            "content-type": "application/json",
            "accept-language": "en",
            "content-language": "en",
            "x-did": self.did,
            "x-sig": make_xsig(self.did, self._pub),
        }
        if self.token:
            h["authorization"] = self.token
        if extra:
            h.update(extra)
        return h

    def login(self, email, password):
        s, b = _http("POST", f"{self.api}/v1/auth/login",
                     {"email": email, "password": password, "reg": False},
                     self._headers({"x-forwarded-for": "192.0.2.1"}))
        if s != 200:
            raise SystemExit(f"login failed HTTP {s}: {b[:200]!r}")
        self.token = json.loads(b)["access_token"]
        return self.token

    def fetch_app(self):
        s, b = _http("GET", f"{self.api}/v1/app?flag=wassvpn", None, self._headers())
        if s != 200:
            raise SystemExit(f"/v1/app failed HTTP {s}: {b[:200]!r}")
        return json.loads(b)

    @staticmethod
    def decrypt_proxy_field(proxy_b64, privkey_pem):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = serialization.load_pem_private_key(privkey_pem, password=None)
        data = base64.b64decode(proxy_b64)
        ksize = key.key_size // 8
        plain = b"".join(key.decrypt(data[i:i + ksize], padding.PKCS1v15())
                         for i in range(0, len(data), ksize))
        return zlib.decompress(plain)


def extract_x365_links(decrypted_yaml_text):
    return re.findall(r'x365://[^\s"\'<>]+', decrypted_yaml_text)


def main():
    ap = argparse.ArgumentParser(prog="x365-cli")
    ap.add_argument("cmd", choices=["login", "nodes", "config"])
    ap.add_argument("--email")
    ap.add_argument("--password")
    ap.add_argument("--did", default=None, help="stable device id (default: random per run)")
    args = ap.parse_args()

    cli = Client(did=args.did or os.environ.get("X365_DID"))

    if args.cmd == "login":
        if not args.email or not args.password:
            ap.error("login requires --email and --password")
        tok = cli.login(args.email, args.password)
        print(tok)
        return

    # nodes/config need credentials
    if not args.email or not args.password:
        ap.error("requires --email and --password")
    cli.login(args.email, args.password)
    app = cli.fetch_app()

    if args.cmd == "config":
        text = Client.decrypt_proxy_field(app["proxy"], open(_PRIVKEY_PATH, "rb").read()).decode()
        print(text)
        return

    # nodes
    text = Client.decrypt_proxy_field(app["proxy"], open(_PRIVKEY_PATH, "rb").read()).decode()
    for l in extract_x365_links(text):
        print(l)


if __name__ == "__main__":
    main()
