"""Deterministic RSA keys and self-signed certificates for the fixtures.

Why this exists: the repository must ship a signed example document and the
certificate that matches it, and it must never ship a private key. GitHub's push
protection rejects a literal ``BEGIN ... PRIVATE KEY`` block, and committing one
would be wrong regardless of whether a scanner noticed.

So the keys are derived, not stored. Each named key comes from a fixed seed
string through ``random.Random``, whose Mersenne Twister output is stable across
CPython releases, so the same seed produces the same modulus on every machine
and every supported Python version. Nothing is written to disk but the
certificate.

These are test keys with published seeds. They are not secret and must never be
used for anything.
"""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import random
from dataclasses import dataclass

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_BASIC_CONSTRAINTS = "2.5.29.19"

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
    89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
]
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(candidate: int) -> bool:
    """Trial division then Miller-Rabin with the first twelve prime bases."""
    if candidate < 2:
        return False
    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    remainder = candidate - 1
    shift = 0
    while remainder % 2 == 0:
        remainder //= 2
        shift += 1
    for base in _MR_BASES:
        value = pow(base, remainder, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shift - 1):
            value = value * value % candidate
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(rng: random.Random, bits: int) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAKey:
    n: int
    e: int
    d: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def sign_pkcs1_sha256(self, message: bytes) -> bytes:
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        digest_info += hashlib.sha256(message).digest()
        padding = b"\xff" * (self.size - len(digest_info) - 3)
        block = b"\x00\x01" + padding + b"\x00" + digest_info
        return pow(int.from_bytes(block, "big"), self.d, self.n).to_bytes(self.size, "big")


@functools.lru_cache(maxsize=None)
def derive_key(seed: str, bits: int = 2048) -> RSAKey:
    """The RSA key for ``seed``. Deterministic, cached per process."""
    rng = random.Random(seed)
    exponent = 65537
    while True:
        p = _prime(rng, bits // 2)
        q = _prime(rng, bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % exponent == 0:
            continue
        return RSAKey(n=p * q, e=exponent, d=pow(exponent, -1, phi))


# ----------------------------------------------------------------- DER encoding
def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def der_integer(value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(size, "big"))


def der_oid(dotted: str) -> bytes:
    parts = [int(piece) for piece in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def der_sequence(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def der_set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(parts))


def der_bitstring(data: bytes) -> bytes:
    return _tlv(0x03, b"\x00" + data)


def der_octetstring(data: bytes) -> bytes:
    return _tlv(0x04, data)


def der_null() -> bytes:
    return _tlv(0x05, b"")


def der_boolean(value: bool) -> bytes:
    return _tlv(0x01, b"\xff" if value else b"\x00")


def der_printable(text: str) -> bytes:
    return _tlv(0x13, text.encode("ascii"))


def der_utf8(text: str) -> bytes:
    return _tlv(0x0C, text.encode("utf-8"))


def der_time(moment: dt.datetime) -> bytes:
    """UTCTime for 1950-2049, GeneralizedTime outside it, as X.509 requires."""
    if 1950 <= moment.year < 2050:
        return _tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def der_name(parts: list[tuple[str, str]]) -> bytes:
    """RDNSequence from (OID, value) pairs, one attribute per RDN."""
    return der_sequence(*[
        der_set(der_sequence(der_oid(oid), der_utf8(value))) for oid, value in parts
    ])


def rsa_public_key_info(key: RSAKey) -> bytes:
    public = der_sequence(der_integer(key.n), der_integer(key.e))
    return der_sequence(
        der_sequence(der_oid(OID_RSA_ENCRYPTION), der_null()),
        der_bitstring(public),
    )


def self_signed_certificate(
    key: RSAKey,
    name: list[tuple[str, str]],
    not_before: dt.datetime,
    not_after: dt.datetime,
    serial: int,
) -> bytes:
    """A v3 self-signed certificate, signed with sha256WithRSAEncryption."""
    algorithm = der_sequence(der_oid(OID_SHA256_WITH_RSA), der_null())
    extensions = _tlv(
        0xA3,
        der_sequence(
            der_sequence(
                der_oid(OID_BASIC_CONSTRAINTS),
                der_boolean(True),
                der_octetstring(der_sequence(der_boolean(True))),
            )
        ),
    )
    tbs = der_sequence(
        _tlv(0xA0, der_integer(2)),
        der_integer(serial),
        algorithm,
        der_name(name),
        der_sequence(der_time(not_before), der_time(not_after)),
        der_name(name),
        rsa_public_key_info(key),
        extensions,
    )
    return der_sequence(tbs, algorithm, der_bitstring(key.sign_pkcs1_sha256(tbs)))


def to_pem(der_bytes: bytes) -> str:
    import base64

    body = base64.b64encode(der_bytes).decode("ascii")
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
