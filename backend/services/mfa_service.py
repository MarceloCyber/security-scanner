"""Small RFC 6238 TOTP implementation with one-time recovery codes."""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def provisioning_uri(username: str, secret: str) -> str:
    issuer = "Iron AI"
    account = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{account}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def current_code(secret: str, timestamp: int | None = None) -> str:
    timestamp = int(time.time() if timestamp is None else timestamp)
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = timestamp // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def verify_code(secret: str, candidate: str, timestamp: int | None = None) -> bool:
    value = "".join(str(candidate or "").split())
    if len(value) != 6 or not value.isdigit():
        return False
    now = int(time.time() if timestamp is None else timestamp)
    return any(hmac.compare_digest(current_code(secret, now + drift * 30), value) for drift in (-1, 0, 1))


def generate_recovery_codes(count: int = 8) -> list[str]:
    return [f"{secrets.token_hex(3).upper()}-{secrets.token_hex(3).upper()}" for _ in range(count)]


def recovery_hash(code: str) -> str:
    return hashlib.sha256(str(code or "").strip().upper().encode()).hexdigest()


def dump_recovery_hashes(codes: list[str]) -> str:
    return json.dumps([recovery_hash(code) for code in codes])


def consume_recovery_code(serialized: str | None, candidate: str) -> tuple[bool, str]:
    try:
        stored = json.loads(serialized or "[]")
    except (TypeError, ValueError):
        stored = []
    candidate_hash = recovery_hash(candidate)
    remaining = [value for value in stored if not hmac.compare_digest(str(value), candidate_hash)]
    return (len(remaining) != len(stored), json.dumps(remaining))
