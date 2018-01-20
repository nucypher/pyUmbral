import pytest

from umbral import umbral, keys


def test_private_key_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.save_key()

    decoded_key = keys.UmbralPrivateKey.load_key(encoded_key,
                                                 umbral.UmbralParameters())

    assert priv_key == decoded_key.bn_key


def test_private_key_serialization_with_encryption():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.save_key(password=b'test')

    decoded_key = keys.UmbralPrivateKey.load_key(encoded_key,
                                                 umbral.UmbralParameters(),
                                                 password=b'test')

    assert priv_key == decoded_key.bn_key


def test_public_key_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    umbral_key = keys.UmbralPublicKey(pub_key)

    encoded_key = umbral_key.save_key()

    decoded_key = keys.UmbralPublicKey.load_key(encoded_key,
                                                umbral.UmbralParameters())

    assert pub_key == decoded_key.point_key
