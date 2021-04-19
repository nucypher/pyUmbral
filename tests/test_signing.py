import pytest

from umbral.keys import PublicKey, SecretKey
from umbral.signing import Signature
from umbral.hashing import Hash


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    digest = Hash(dst)
    digest.update(message)
    assert signature.verify_digest(pk, digest)


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_serialize_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    signature_bytes = bytes(signature)
    signature_restored = Signature.from_bytes(signature_bytes)

    digest = Hash(dst)
    digest.update(message)
    assert signature_restored.verify_digest(pk, digest)


def test_verification_fail():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    # wrong DST
    digest = Hash(b"other dst")
    digest.update(message)
    assert not signature.verify_digest(pk, digest)

    # wrong message
    digest = Hash(dst)
    digest.update(b"no peace at dawn")
    assert not signature.verify_digest(pk, digest)

    # bad signature
    signature_bytes = bytes(signature)
    signature_bytes = b'\x00' + signature_bytes[1:]
    signature_restored = Signature.from_bytes(signature_bytes)

    digest = Hash(dst)
    digest.update(message)
    assert not signature_restored.verify_digest(pk, digest)


def test_signature_repr():

    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)

    message = b"peace at dawn"
    dst = b"dst"

    digest = Hash(dst)
    digest.update(message)
    signature = sk.sign_digest(digest)

    s = repr(signature)
    assert 'Signature' in s
