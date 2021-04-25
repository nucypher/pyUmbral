import pytest

from umbral.keys import PublicKey, SecretKey
from umbral.signing import Signature, Signer
from umbral.hashing import Hash


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)

    message = b"peace at dawn" + str(execution_number).encode()

    signature = signer.sign(message)
    assert signature.verify(pk, message)


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_serialize_and_verify(execution_number):
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)

    message = b"peace at dawn" + str(execution_number).encode()

    signature = signer.sign(message)

    signature_bytes = bytes(signature)
    signature_restored = Signature.from_bytes(signature_bytes)

    assert signature_restored.verify(pk, message)


def test_verification_fail():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)

    message = b"peace at dawn"
    signature = signer.sign(message)

    # wrong message
    wrong_message = b"no peace at dawn"
    assert not signature.verify(pk, wrong_message)

    # bad signature
    signature_bytes = bytes(signature)
    signature_bytes = b'\x00' + signature_bytes[1:]
    signature_restored = Signature.from_bytes(signature_bytes)

    assert not signature_restored.verify(pk, message)


def test_signature_str():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)
    signature = signer.sign(b'peace at dawn')
    s = str(signature)
    assert 'Signature' in s


def test_signature_is_hashable():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)

    message = b'peace at dawn'
    message2 = b'no peace at dawn'

    signature = signer.sign(message)
    signature2 = signer.sign(message2)

    assert hash(signature) != hash(signature2)

    signature_restored = Signature.from_bytes(bytes(signature))
    assert signature == signature_restored
    assert hash(signature) == hash(signature_restored)

    # Different hash, since signing involves some randomness
    signature3 = signer.sign(message)
    assert hash(signature) != hash(signature3)


def test_signer_str():
    signer = Signer(SecretKey.random())
    s = str(signer)
    assert s == "Signer:..."


def test_signer_hash():
    signer = Signer(SecretKey.random())
    # Insecure Python hash, shouldn't be available.
    with pytest.raises(RuntimeError):
        hash(signer)


def test_signer_bytes():
    signer = Signer(SecretKey.random())
    # Shouldn't be able to serialize.
    with pytest.raises(RuntimeError):
        bytes(signer)


def test_signer_pubkey():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    signer = Signer(sk)
    assert signer.verifying_key() == pk
