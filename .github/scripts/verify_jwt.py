#!/usr/bin/env python3
"""Verify an RS256 access token against the service's published JWKS.

This mirrors downstream verification without importing a SignaCore assembly. It uses
only the Python standard library so CI does not need an extra network dependency.

Usage: verify_jwt.py <token-file> <jwks-file> <issuer> <audience>

The script intentionally prints neither the token nor the complete payload because
public-repository workflow logs are visible to everyone.
"""

import base64
import hashlib
import json
import sys
import time

# SHA-256 DigestInfo DER prefix for PKCS#1 v1.5 (RFC 8017 section 9.2).
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# Issued tokens use standard short claim names for non-.NET consumers.
SUBJECT_CLAIM_NAME = "sub"
CLIENT_ID_CLAIM_NAME = "client_id"
LEGACY_CLAIM_PREFIX = "http://schemas."


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fail(message: str) -> None:
    print(f"JWT VERIFY FAIL: {message}")
    sys.exit(1)


def verify_rs256(signing_input: bytes, signature: bytes, modulus: int, exponent: int) -> bool:
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        return False

    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_size, "big")
    digest = hashlib.sha256(signing_input).digest()
    suffix = SHA256_DIGEST_INFO_PREFIX + digest
    padding_length = key_size - len(suffix) - 3
    if padding_length < 8:
        return False

    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + suffix
    return encoded == expected


def main() -> None:
    if len(sys.argv) != 5:
        fail("usage: verify_jwt.py <token-file> <jwks-file> <issuer> <audience>")

    token = open(sys.argv[1], encoding="utf-8").read().strip()
    jwks = json.load(open(sys.argv[2], encoding="utf-8"))
    expected_issuer, expected_audience = sys.argv[3], sys.argv[4]

    parts = token.split(".")
    if len(parts) != 3:
        fail(f"token is not a three-part JWT (received {len(parts)} parts)")

    header = json.loads(b64url_decode(parts[0]))
    if header.get("alg") != "RS256":
        fail(f"algorithm is not RS256: {header.get('alg')}")

    kid = header.get("kid")
    if not kid:
        fail("header has no kid, so a consumer cannot locate the JWKS key")

    key = next((item for item in jwks.get("keys", []) if item.get("kid") == kid), None)
    if key is None:
        published = [item.get("kid") for item in jwks.get("keys", [])]
        fail(f"JWKS has no kid={kid}; published keys are {published}")
    if key.get("kty") != "RSA":
        fail(f"kid={kid} does not have RSA key type: {key.get('kty')}")

    modulus = int.from_bytes(b64url_decode(key["n"]), "big")
    exponent = int.from_bytes(b64url_decode(key["e"]), "big")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    if not verify_rs256(signing_input, b64url_decode(parts[2]), modulus, exponent):
        fail(f"signature verification failed for kid={kid}")

    payload = json.loads(b64url_decode(parts[1]))
    if payload.get("iss") != expected_issuer:
        fail(f"issuer mismatch: expected {expected_issuer}, got {payload.get('iss')}")

    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if expected_audience not in audiences:
        fail(f"audience mismatch: expected {expected_audience}, got {audience}")

    if not payload.get(SUBJECT_CLAIM_NAME):
        fail(f"payload lacks {SUBJECT_CLAIM_NAME}; claims={sorted(payload)}")
    if not payload.get(CLIENT_ID_CLAIM_NAME):
        fail(f"payload lacks {CLIENT_ID_CLAIM_NAME}; claims={sorted(payload)}")

    legacy = [name for name in payload if name.startswith(LEGACY_CLAIM_PREFIX)]
    if legacy:
        fail(f"token contains legacy ClaimTypes URI names: {sorted(legacy)}")

    expires_at = payload.get("exp")
    if not isinstance(expires_at, int):
        fail(f"exp is missing or is not an integer: {expires_at}")
    if expires_at <= time.time():
        fail(f"token is expired: exp={expires_at}, now={int(time.time())}")

    # Print claim names, not values that may contain personal data.
    print(
        f"JWT verified: alg=RS256, kid={kid}, iss={payload['iss']}, "
        f"aud={expected_audience}, expires_in={expires_at - int(time.time())}s, "
        f"claims={sorted(payload)}"
    )


if __name__ == "__main__":
    main()
