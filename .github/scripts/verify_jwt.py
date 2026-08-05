#!/usr/bin/env python3
"""用 /.well-known/jwks 发布的公钥验证一枚 RS256 access token。

这正是下游业务微服务做的事：它们不引用本仓库任何程序集，只拉 JWKS 本地验签。
验签一旦对不上，所有下游会同时失效，所以冒烟里必须真的验一次，而不是只看
token 非空。

只用标准库：RSA 验签就是 sig^e mod n，再比对 PKCS#1 v1.5 的 EMSA 填充。
托管 runner 不保证装了 cryptography，多一个 pip install 就多一处可失败的网络依赖。

用法：verify_jwt.py <token 文件> <jwks 文件> <期望 issuer> <期望 audience>

刻意不打印 token 本身和完整 payload——本仓库是 public repo，workflow 日志全网可读。
"""

import base64
import hashlib
import json
import sys
import time

# PKCS#1 v1.5 里 SHA-256 的 DigestInfo DER 前缀（RFC 8017 §9.2）
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# 签发的 token 一律用标准短名。这里不再接受 nameid 或 .NET 的长 URI：
# 契约既然定了，就让偏离它的改动在 CI 上直接失败。
SUBJECT_CLAIM_NAME = "sub"

# 回退护栏：claim 名字一旦又变成 ClaimTypes.* 的完整 XML schema URI，立刻报错。
# 长 URI 只有开着 MapInboundClaims 的 .NET 下游能无感消费，非 .NET 下游会踩坑。
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
        fail(f"token 不是三段式 JWT（拿到 {len(parts)} 段）")

    header = json.loads(b64url_decode(parts[0]))
    if header.get("alg") != "RS256":
        fail(f"alg 不是 RS256：{header.get('alg')}")

    kid = header.get("kid")
    if not kid:
        fail("header 里没有 kid，下游无法在 JWKS 中定位公钥")

    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        published = [k.get("kid") for k in jwks.get("keys", [])]
        fail(f"JWKS 里找不到 kid={kid}，已发布的是 {published}")
    if key.get("kty") != "RSA":
        fail(f"kid={kid} 的 kty 不是 RSA：{key.get('kty')}")

    modulus = int.from_bytes(b64url_decode(key["n"]), "big")
    exponent = int.from_bytes(b64url_decode(key["e"]), "big")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    if not verify_rs256(signing_input, b64url_decode(parts[2]), modulus, exponent):
        fail(f"签名验证失败（kid={kid}）——JWKS 公钥与签名私钥对不上")

    payload = json.loads(b64url_decode(parts[1]))

    if payload.get("iss") != expected_issuer:
        fail(f"iss 不匹配：期望 {expected_issuer}，实际 {payload.get('iss')}")

    # aud 可能是字符串也可能是数组，两种都要接住
    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if expected_audience not in audiences:
        fail(f"aud 不匹配：期望 {expected_audience}，实际 {audience}")

    if not payload.get(SUBJECT_CLAIM_NAME):
        fail(f"payload 缺 {SUBJECT_CLAIM_NAME}，claims={sorted(payload)}")

    legacy = [name for name in payload if name.startswith(LEGACY_CLAIM_PREFIX)]
    if legacy:
        fail(f"token 里出现了 ClaimTypes.* 长 URI，应为标准短名：{sorted(legacy)}")

    expires_at = payload.get("exp")
    if not isinstance(expires_at, int):
        fail(f"exp 缺失或不是整数：{expires_at}")
    if expires_at <= time.time():
        fail(f"token 已过期：exp={expires_at}, now={int(time.time())}")

    # 只打 claim 名字，不打值——值里可能有手机号等敏感信息，而本仓库是 public repo。
    # 打出来是为了让 token 的实际形状在日志里有据可查：谁改动了 claim 集合，
    # 这一行会立刻显出来。
    print(
        f"JWT verified: alg=RS256, kid={kid}, iss={payload['iss']}, "
        f"aud={expected_audience}, expires_in={expires_at - int(time.time())}s, "
        f"claims={sorted(payload)}"
    )


if __name__ == "__main__":
    main()
