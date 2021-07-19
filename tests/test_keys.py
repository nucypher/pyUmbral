import os
import string

import pytest

from umbral.keys import PublicKey, SecretKey, SecretKeyFactory


def test_gen_key():
    sk = SecretKey.random()
    assert type(sk) == SecretKey

    pk = sk.public_key()
    assert type(pk) == PublicKey

    pk2 = sk.public_key()
    assert pk == pk2


def test_secret_scalar():
    sk = SecretKey.random()
    assert sk.secret_scalar() == sk._scalar_key


def test_derive_key_from_label():
    factory = SecretKeyFactory.random()

    label = b"my_healthcare_information"

    sk1 = factory.secret_key_by_label(label)
    assert type(sk1) == SecretKey

    pk1 = sk1.public_key()
    assert type(pk1) == PublicKey

    # Check that key derivation is reproducible
    sk2 = factory.secret_key_by_label(label)
    pk2 = sk2.public_key()
    assert sk1 == sk2
    assert pk1 == pk2

    # Different labels on the same master secret create different keys
    label = b"my_tax_information"
    sk3 = factory.secret_key_by_label(label)
    pk3 = sk3.public_key()
    assert sk1 != sk3


def test_secret_key_serialization():
    sk = SecretKey.random()
    encoded_key = sk.to_secret_bytes()
    decoded_key = SecretKey.from_bytes(encoded_key)
    assert sk == decoded_key


def test_secret_key_str():
    sk = SecretKey.random()
    s = str(sk)
    assert s == "SecretKey:..."


def test_secret_key_hash():
    sk = SecretKey.random()
    # Insecure Python hash, shouldn't be available.
    with pytest.raises(RuntimeError):
        hash(sk)


def test_secret_key_factory_str():
    skf = SecretKeyFactory.random()
    s = str(skf)
    assert s == "SecretKeyFactory:..."


def test_secret_key_factory_hash():
    skf = SecretKeyFactory.random()
    # Insecure Python hash, shouldn't be available.
    with pytest.raises(RuntimeError):
        hash(skf)


def test_public_key_serialization():
    sk = SecretKey.random()
    pk = sk.public_key()

    encoded_key = bytes(pk)
    decoded_key = PublicKey.from_bytes(encoded_key)
    assert pk == decoded_key


def test_public_key_point():
    pk = SecretKey.random().public_key()
    assert bytes(pk) == bytes(pk.point())


def test_public_key_str():
    pk = SecretKey.random().public_key()
    s = str(pk)
    assert 'PublicKey' in s


def test_secret_key_factory_serialization():
    factory = SecretKeyFactory.random()

    encoded_factory = factory.to_secret_bytes()
    decoded_factory = SecretKeyFactory.from_bytes(encoded_factory)

    label = os.urandom(32)
    sk1 = factory.secret_key_by_label(label)
    sk2 = decoded_factory.secret_key_by_label(label)
    assert sk1 == sk2


def test_public_key_is_hashable():
    sk = SecretKey.random()
    pk = sk.public_key()

    sk2 = SecretKey.random()
    pk2 = sk2.public_key()
    assert hash(pk) != hash(pk2)

    pk3 = PublicKey.from_bytes(bytes(pk))
    assert hash(pk) == hash(pk3)
