"""The DER/ASN.1 reader and the X.509 fields the tool depends on.

The certificates these tests read are the ones the repository ships, and they
are rebuilt here from their seeds, so a change to either side fails.
"""

from __future__ import annotations

import datetime as dt
import unittest

from saml_xsw_lint import der
from tools import keys, samlfixtures

from .helpers import read_cert


class Primitives(unittest.TestCase):
    def test_oid_decoding(self):
        self.assertEqual("1.2.840.113549.1.1.1",
                         der.decode_oid(bytes.fromhex("2a864886f70d010101")))
        self.assertEqual("2.5.4.3", der.decode_oid(bytes.fromhex("550403")))
        self.assertEqual("1.2.840.113549.1.1.11",
                         der.decode_oid(bytes.fromhex("2a864886f70d01010b")))

    def test_oid_rejects_truncated_encoding(self):
        with self.assertRaises(der.DERError):
            der.decode_oid(bytes.fromhex("2a86"))
        with self.assertRaises(der.DERError):
            der.decode_oid(b"")

    def test_sequence_of_integers(self):
        node = der.parse_der(bytes.fromhex("3006020101020102"))
        self.assertEqual(der.TAG_SEQUENCE, node.tag)
        self.assertTrue(node.constructed)
        self.assertEqual([1, 2], [child.int_value for child in node.children])

    def test_long_form_length(self):
        body = b"\x04\x82" + (200).to_bytes(2, "big") + b"\x00" * 200
        node = der.parse_der(body)
        self.assertEqual(der.TAG_OCTET_STRING, node.tag)
        self.assertEqual(200, len(node.value))

    def test_trailing_bytes_are_rejected(self):
        with self.assertRaises(der.DERError):
            der.parse_der(bytes.fromhex("3003020101") + b"\x00")

    def test_truncated_value_is_rejected(self):
        with self.assertRaises(der.DERError):
            der.parse_der(bytes.fromhex("3006020101"))

    def test_high_tag_number_form_is_rejected(self):
        with self.assertRaises(der.DERError):
            der.parse_der(b"\x1f\x01\x00")

    def test_int_value_requires_an_integer(self):
        node = der.parse_der(b"\x04\x01\x05")
        with self.assertRaises(der.DERError):
            self.assertIsNone(node.int_value)

    def test_missing_child_is_an_error(self):
        with self.assertRaises(der.DERError):
            der.parse_der(bytes.fromhex("3003020101")).child(3)


class Times(unittest.TestCase):
    def test_utctime_two_digit_year_below_fifty_is_twenty_first_century(self):
        node = der.parse_der(b"\x17\x0d" + b"260115120000Z")
        self.assertEqual(dt.datetime(2026, 1, 15, 12, 0, tzinfo=dt.timezone.utc),
                         der.parse_time(node))

    def test_utctime_two_digit_year_from_fifty_is_twentieth_century(self):
        node = der.parse_der(b"\x17\x0d" + b"970115120000Z")
        self.assertEqual(1997, der.parse_time(node).year)

    def test_generalizedtime(self):
        node = der.parse_der(b"\x18\x0f" + b"20510115120000Z")
        self.assertEqual(2051, der.parse_time(node).year)

    def test_short_time_is_rejected(self):
        with self.assertRaises(der.DERError):
            der.parse_time(der.parse_der(b"\x17\x04" + b"2601"))

    def test_wrong_type_is_rejected(self):
        with self.assertRaises(der.DERError):
            der.parse_time(der.parse_der(b"\x02\x01\x01"))


class ShippedCertificates(unittest.TestCase):
    def test_idp_certificate_fields(self):
        certificate = der.Certificate.from_der(read_cert("idp"))
        self.assertIn("CN=idp.example", certificate.subject)
        self.assertIn("O=Example Identity Provider", certificate.subject)
        self.assertEqual(certificate.subject, certificate.issuer)
        self.assertTrue(certificate.is_self_issued)
        self.assertEqual(2026, certificate.not_before.year)
        self.assertEqual(2046, certificate.not_after.year)
        self.assertEqual("RSA", certificate.public_key.algorithm_name)
        self.assertEqual(2048, certificate.public_key.bits)
        self.assertEqual(65537, certificate.public_key.exponent)
        self.assertEqual("rsa-sha256", certificate.signature_algorithm_name)
        self.assertEqual(64, len(certificate.sha256_fingerprint) // 1)

    def test_idp_certificate_self_signature_verifies(self):
        certificate = der.Certificate.from_der(read_cert("idp"))
        self.assertIs(True, certificate.verify_self_signature())

    def test_other_idp_uses_generalizedtime_and_a_different_key(self):
        other = der.Certificate.from_der(read_cert("other-idp"))
        idp = der.Certificate.from_der(read_cert("idp"))
        self.assertEqual(2051, other.not_after.year)
        self.assertNotEqual(idp.public_key.modulus, other.public_key.modulus)
        self.assertNotEqual(idp.sha256_fingerprint, other.sha256_fingerprint)
        self.assertIs(True, other.verify_self_signature())

    def test_expired_certificate_window(self):
        certificate = der.Certificate.from_der(read_cert("expired-idp"))
        now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        self.assertTrue(certificate.is_expired(now))
        self.assertFalse(certificate.is_not_yet_valid(now))
        self.assertTrue(certificate.is_not_yet_valid(dt.datetime(2007, 1, 1, tzinfo=dt.timezone.utc)))

    def test_weak_certificate_is_1024_bits(self):
        certificate = der.Certificate.from_der(read_cert("weak-idp"))
        self.assertEqual(1024, certificate.public_key.bits)
        self.assertIs(True, certificate.verify_self_signature())

    def test_committed_certificates_match_their_seeds(self):
        for name in samlfixtures.CERTIFICATES:
            with self.subTest(name=name):
                self.assertEqual(samlfixtures.certificate_der(name), read_cert(name))

    def test_pem_and_der_loading_agree(self):
        pem = (samlfixtures.certificate_pem("idp")).encode("ascii")
        self.assertEqual(samlfixtures.certificate_der("idp"), der.load_certificate_file(pem))
        self.assertEqual(samlfixtures.certificate_der("idp"),
                         der.load_certificate_file(samlfixtures.certificate_der("idp")))

    def test_garbage_is_not_a_certificate(self):
        with self.assertRaises((der.DERError, ValueError)):
            der.Certificate.from_der(b"not a certificate at all")


class Signatures(unittest.TestCase):
    def setUp(self):
        self.key = keys.derive_key(samlfixtures.CERTIFICATES["idp"].seed, 2048)

    def test_round_trip_sign_and_verify(self):
        message = b"canonicalised SignedInfo would go here"
        signature = self.key.sign_pkcs1_sha256(message)
        self.assertEqual(256, len(signature))
        self.assertTrue(der.rsa_pkcs1_verify(self.key.n, self.key.e, signature, message, "sha256"))

    def test_verification_fails_on_a_changed_message(self):
        signature = self.key.sign_pkcs1_sha256(b"original")
        self.assertFalse(der.rsa_pkcs1_verify(self.key.n, self.key.e, signature, b"changed", "sha256"))

    def test_verification_fails_on_a_changed_signature(self):
        signature = bytearray(self.key.sign_pkcs1_sha256(b"original"))
        signature[-1] ^= 0x01
        self.assertFalse(
            der.rsa_pkcs1_verify(self.key.n, self.key.e, bytes(signature), b"original", "sha256")
        )

    def test_verification_rejects_a_wrong_length_signature(self):
        signature = self.key.sign_pkcs1_sha256(b"original")
        self.assertFalse(der.rsa_pkcs1_verify(self.key.n, self.key.e, signature[:-1],
                                              b"original", "sha256"))

    def test_verification_rejects_a_different_key(self):
        other = keys.derive_key(samlfixtures.CERTIFICATES["other-idp"].seed, 2048)
        signature = self.key.sign_pkcs1_sha256(b"original")
        self.assertFalse(der.rsa_pkcs1_verify(other.n, other.e, signature, b"original", "sha256"))

    def test_unsupported_digest_is_an_error(self):
        with self.assertRaises(ValueError):
            der.rsa_pkcs1_verify(self.key.n, self.key.e, b"\x00" * 256, b"x", "sha3-256")

    def test_keys_are_deterministic_across_calls(self):
        again = keys.derive_key(samlfixtures.CERTIFICATES["idp"].seed, 2048)
        self.assertEqual(self.key.n, again.n)
        self.assertEqual(self.key.d, again.d)

    def test_different_seeds_give_different_keys(self):
        other = keys.derive_key("some other seed", 1024)
        self.assertNotEqual(self.key.n, other.n)


class PrimeGeneration(unittest.TestCase):
    def test_known_primes_and_composites(self):
        for value in (2, 3, 5, 65537, 2 ** 61 - 1):
            self.assertTrue(keys._is_probable_prime(value), value)
        for value in (1, 4, 9, 21, 65536, (2 ** 31 - 1) * 3):
            self.assertFalse(keys._is_probable_prime(value), value)


if __name__ == "__main__":
    unittest.main()
