"""A small DER/ASN.1 reader and just enough X.509 to answer three questions.

The three questions are: how big is the public key, when does the certificate
expire, and is it self-signed? Answering them needs no third-party library and
no network, which is the whole point - ``cryptography`` would be a dependency
and OpenSSL's ``x509`` would be a subprocess.

What this is not: a validator. There is no chain building, no name constraints,
no key usage enforcement, no revocation. ``verify_self_signature`` checks one
RSA PKCS#1 v1.5 signature against the certificate's own public key and nothing
else.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from dataclasses import dataclass, field

CLASS_UNIVERSAL = 0x00
CLASS_CONTEXT = 0x80

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8STRING = 0x0C
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_PRINTABLESTRING = 0x13
TAG_T61STRING = 0x14
TAG_IA5STRING = 0x16
TAG_UTCTIME = 0x17
TAG_GENERALIZEDTIME = 0x18
TAG_BMPSTRING = 0x1E

_STRING_TAGS = {TAG_UTF8STRING, TAG_PRINTABLESTRING, TAG_T61STRING, TAG_IA5STRING, TAG_BMPSTRING}

OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_DSA = "1.2.840.10040.4.1"

RSA_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5",
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}

SIG_ALG_NAMES = {
    **{oid: f"rsa-{name}" for oid, name in RSA_SIG_OIDS.items()},
    "1.2.840.10040.4.3": "dsa-sha1",
    "1.2.840.10045.4.3.2": "ecdsa-sha256",
    "1.2.840.10045.4.3.3": "ecdsa-sha384",
    "1.2.840.10045.4.3.4": "ecdsa-sha512",
}

CURVE_BITS = {
    "1.2.840.10045.3.1.7": 256,
    "1.3.132.0.34": 384,
    "1.3.132.0.35": 521,
}

#: DigestInfo prefixes for PKCS#1 v1.5 (RFC 8017 appendix B.1).
DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class DERError(ValueError):
    """Malformed DER."""


@dataclass
class Node:
    """One TLV."""

    tag_class: int
    constructed: bool
    tag: int
    value: bytes
    #: The complete encoding of this node, header included.
    encoding: bytes
    children: list[Node] = field(default_factory=list)

    def child(self, index: int) -> Node:
        try:
            return self.children[index]
        except IndexError:
            raise DERError(f"expected a child at index {index}") from None

    @property
    def int_value(self) -> int:
        if self.tag != TAG_INTEGER or self.tag_class != CLASS_UNIVERSAL:
            raise DERError("not an INTEGER")
        return int.from_bytes(self.value, "big", signed=True)

    @property
    def oid_value(self) -> str:
        if self.tag != TAG_OID:
            raise DERError("not an OBJECT IDENTIFIER")
        return decode_oid(self.value)

    @property
    def text_value(self) -> str:
        if self.tag == TAG_BMPSTRING:
            return self.value.decode("utf-16-be", "replace")
        return self.value.decode("utf-8", "replace")


def decode_oid(data: bytes) -> str:
    if not data:
        raise DERError("empty OID")
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for index, byte in enumerate(data[1:], start=1):
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
        elif index == len(data) - 1:
            raise DERError("truncated OID")
    return ".".join(parts)


def _parse_one(data: bytes, offset: int, depth: int) -> tuple[Node, int]:
    if depth > 40:
        raise DERError("nesting too deep")
    if offset >= len(data):
        raise DERError("truncated at header")
    identifier = data[offset]
    tag_class = identifier & 0xC0
    constructed = bool(identifier & 0x20)
    tag = identifier & 0x1F
    if tag == 0x1F:
        raise DERError("high-tag-number form is not supported")
    position = offset + 1
    if position >= len(data):
        raise DERError("truncated at length")
    first = data[position]
    position += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DERError("unsupported length encoding")
        if position + count > len(data):
            raise DERError("truncated length")
        length = int.from_bytes(data[position:position + count], "big")
        position += count
    else:
        length = first
    end = position + length
    if end > len(data):
        raise DERError("truncated value")
    value = data[position:end]
    node = Node(tag_class=tag_class, constructed=constructed, tag=tag,
                value=value, encoding=data[offset:end])
    if constructed:
        inner = position
        while inner < end:
            child, inner = _parse_one(data, inner, depth + 1)
            node.children.append(child)
    return node, end


def parse_der(data: bytes) -> Node:
    """Parse a single DER object. Trailing bytes are an error."""
    node, end = _parse_one(data, 0, 0)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing byte(s) after the top-level object")
    return node


def parse_time(node: Node) -> dt.datetime:
    """UTCTime or GeneralizedTime -> aware datetime in UTC."""
    text = node.value.decode("ascii", "replace")
    if node.tag == TAG_UTCTIME:
        if len(text) < 11:
            raise DERError(f"short UTCTime: {text!r}")
        year = int(text[0:2])
        year += 2000 if year < 50 else 1900
        rest = text[2:]
    elif node.tag == TAG_GENERALIZEDTIME:
        if len(text) < 13:
            raise DERError(f"short GeneralizedTime: {text!r}")
        year = int(text[0:4])
        rest = text[4:]
    else:
        raise DERError("not a time type")
    month, day, hour, minute = (int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]))
    second = 0
    tail = rest[8:]
    if tail[:2].isdigit():
        second = int(tail[:2])
    return dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)


def _name_to_text(name: Node) -> str:
    parts = []
    for rdn in name.children:
        for attribute in rdn.children:
            try:
                oid = attribute.child(0).oid_value
                value = attribute.child(1)
            except DERError:
                continue
            label = OID_NAMES.get(oid, oid)
            text = value.text_value if value.tag in _STRING_TAGS else value.value.hex()
            parts.append(f"{label}={text}")
    return ", ".join(parts)


@dataclass
class PublicKey:
    algorithm: str
    bits: int
    #: RSA only.
    modulus: int | None = None
    exponent: int | None = None
    curve: str | None = None

    @property
    def algorithm_name(self) -> str:
        return {OID_RSA: "RSA", OID_EC: "EC", OID_DSA: "DSA"}.get(self.algorithm, self.algorithm)


@dataclass
class Certificate:
    der: bytes
    tbs: bytes
    serial: int
    issuer: str
    subject: str
    not_before: dt.datetime
    not_after: dt.datetime
    public_key: PublicKey
    signature_algorithm: str
    signature: bytes

    @property
    def is_self_issued(self) -> bool:
        """Issuer equals subject. Says nothing about the signature."""
        return self.issuer == self.subject

    @property
    def sha256_fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def signature_algorithm_name(self) -> str:
        return SIG_ALG_NAMES.get(self.signature_algorithm, self.signature_algorithm)

    def is_expired(self, now: dt.datetime) -> bool:
        return now >= self.not_after

    def is_not_yet_valid(self, now: dt.datetime) -> bool:
        return now < self.not_before

    def verify_self_signature(self) -> bool | None:
        """Verify this certificate against its own public key.

        Returns ``True``/``False`` for RSA PKCS#1 v1.5 with a hash this module
        knows, and ``None`` when the algorithm is outside that set (so a caller
        can distinguish "bad" from "not checked").
        """
        digest_name = RSA_SIG_OIDS.get(self.signature_algorithm)
        key = self.public_key
        if digest_name is None or key.modulus is None or key.exponent is None:
            return None
        if digest_name not in DIGEST_INFO_PREFIX:
            return None
        return rsa_pkcs1_verify(key.modulus, key.exponent, self.signature, self.tbs, digest_name)

    @classmethod
    def from_der(cls, der: bytes) -> Certificate:
        top = parse_der(der)
        if not top.constructed or top.tag != TAG_SEQUENCE:
            raise DERError("certificate is not a SEQUENCE")
        tbs = top.child(0)
        index = 0
        if tbs.children and tbs.child(0).tag_class == CLASS_CONTEXT and tbs.child(0).tag == 0:
            index = 1
        serial = tbs.child(index).int_value
        index += 1
        index += 1  # inner signature AlgorithmIdentifier, must equal the outer one
        issuer = _name_to_text(tbs.child(index))
        index += 1
        validity = tbs.child(index)
        index += 1
        subject = _name_to_text(tbs.child(index))
        index += 1
        spki = tbs.child(index)

        algorithm = spki.child(0).child(0).oid_value
        bit_string = spki.child(1)
        if bit_string.tag != TAG_BIT_STRING or not bit_string.value:
            raise DERError("subjectPublicKey is not a BIT STRING")
        key_bytes = bit_string.value[1:]
        if algorithm == OID_RSA:
            rsa = parse_der(key_bytes)
            modulus = rsa.child(0).int_value
            exponent = rsa.child(1).int_value
            key = PublicKey(algorithm=algorithm, bits=modulus.bit_length(),
                            modulus=modulus, exponent=exponent)
        elif algorithm == OID_EC:
            curve = spki.child(0).child(1).oid_value if len(spki.child(0).children) > 1 else None
            key = PublicKey(algorithm=algorithm, bits=CURVE_BITS.get(curve or "", 0), curve=curve)
        else:
            key = PublicKey(algorithm=algorithm, bits=0)

        outer_alg = top.child(1).child(0).oid_value
        signature_bits = top.child(2)
        if signature_bits.tag != TAG_BIT_STRING or not signature_bits.value:
            raise DERError("signatureValue is not a BIT STRING")
        return cls(
            der=der,
            tbs=tbs.encoding,
            serial=serial,
            issuer=issuer,
            subject=subject,
            not_before=parse_time(validity.child(0)),
            not_after=parse_time(validity.child(1)),
            public_key=key,
            signature_algorithm=outer_alg,
            signature=signature_bits.value[1:],
        )


def rsa_pkcs1_verify(modulus: int, exponent: int, signature: bytes, message: bytes,
                     digest_name: str) -> bool:
    """RSASSA-PKCS1-v1_5 verification, written out so it stays dependency-free.

    The padding is rebuilt and compared in full rather than parsed, which avoids
    the class of bug where a verifier accepts a loosely-padded signature.
    """
    prefix = DIGEST_INFO_PREFIX.get(digest_name)
    if prefix is None:
        raise ValueError(f"unsupported digest {digest_name!r}")
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size or size < len(prefix) + hashlib.new(digest_name).digest_size + 11:
        return False
    recovered = pow(int.from_bytes(signature, "big"), exponent, modulus)
    candidate = recovered.to_bytes(size, "big")
    digest_info = prefix + hashlib.new(digest_name, message).digest()
    padding = b"\xff" * (size - len(digest_info) - 3)
    return candidate == b"\x00\x01" + padding + b"\x00" + digest_info


def der_from_base64(text: str) -> bytes:
    """Decode the base64 body of an X509Certificate element or a PEM block."""
    lines = [line.strip() for line in text.strip().splitlines()]
    body = "".join(line for line in lines if line and not line.startswith("-----"))
    return base64.b64decode(body + "=" * (-len(body) % 4))


def load_certificate_file(data: bytes) -> bytes:
    """Return DER from a file that may be PEM or DER."""
    if data.lstrip().startswith(b"-----"):
        return der_from_base64(data.decode("ascii", "replace"))
    return data
