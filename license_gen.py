#!/usr/bin/env python3
"""
license_gen.py — EZ-Kea license key generator (vendor-side CLI tool).
Keep the private key OFFLINE and NEVER distribute it with the application.

Usage:
  python license_gen.py --licensee "Acme Corp" --email admin@acme.com \
      --expires 2026-12-31 --max-leases 0
"""
import argparse, base64, json
from datetime import date
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

LICENSE_PREFIX = "EZK1."
PRIVATE_KEY_PATH = "keys/private.pem"


def generate(licensee: str, email: str, expires: str, max_leases: int, features: list) -> str:
    payload = json.dumps({
        "id":         f"EZK-{date.today().strftime('%Y%m%d')}-{licensee[:4].upper()}",
        "licensee":   licensee,
        "email":      email,
        "issued":     str(date.today()),
        "expires":    expires,
        "max_leases": max_leases,
        "features":   features,
    }, separators=(",", ":")).encode()

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    sig = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    p64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    s64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{LICENSE_PREFIX}{p64}.{s64}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate an EZ-Kea license key")
    ap.add_argument("--licensee",   required=True)
    ap.add_argument("--email",      required=True)
    ap.add_argument("--expires",    required=True, help="YYYY-MM-DD")
    ap.add_argument("--max-leases", type=int, default=0, help="0=unlimited")
    ap.add_argument("--features",   nargs="*", default=[])
    args = ap.parse_args()
    key = generate(args.licensee, args.email, args.expires, args.max_leases, args.features)
    print(key)
