import base64

import pytest

from umbral import pre, keys
from umbral.config import default_params
from umbral.keys import UmbralPublicKey


def test_gen_key():
    # Pass in the parameters to test that manual param selection works
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    assert type(umbral_priv_key) == keys.UmbralPrivateKey

    umbral_pub_key = umbral_priv_key.get_pubkey()
    assert type(umbral_pub_key) == keys.UmbralPublicKey


def test_private_key_serialization(random_ec_bignum1):
    priv_key = random_ec_bignum1
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.to_bytes()

    decoded_key = keys.UmbralPrivateKey.from_bytes(encoded_key)
    assert priv_key == decoded_key.bn_key


def test_private_key_serialization_with_encryption(random_ec_bignum1):
    priv_key = random_ec_bignum1
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.to_bytes(password=b'test')

    decoded_key = keys.UmbralPrivateKey.from_bytes(encoded_key, password=b'test')
    assert priv_key == decoded_key.bn_key


def test_public_key_serialization(random_ec_bignum1):
    priv_key = random_ec_bignum1

    params = default_params()
    pub_key = priv_key * params.g

    umbral_key = keys.UmbralPublicKey(pub_key)

    encoded_key = umbral_key.to_bytes()

    decoded_key = keys.UmbralPublicKey.from_bytes(encoded_key)
    assert pub_key == decoded_key.point_key


def test_public_key_to_bytes(random_ec_bignum1):
    priv_key = random_ec_bignum1
    
    params = default_params()
    pub_key = priv_key * params.g

    umbral_key = keys.UmbralPublicKey(pub_key)
    key_bytes = bytes(umbral_key)

    assert type(key_bytes) == bytes


def test_key_encoder_decoder(random_ec_bignum1):
    priv_key = random_ec_bignum1
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.to_bytes(encoder=base64.urlsafe_b64encode)

    decoded_key = keys.UmbralPrivateKey.from_bytes(encoded_key,
                                                   decoder=base64.urlsafe_b64decode)
    assert decoded_key.to_bytes() == umbral_key.to_bytes()


def test_umbral_key_to_cryptography_keys():
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    crypto_privkey = umbral_priv_key.to_cryptography_privkey()
    assert int(umbral_priv_key.bn_key) == crypto_privkey.private_numbers().private_value

    crypto_pubkey = umbral_pub_key.to_cryptography_pubkey()
    umbral_affine = umbral_pub_key.point_key.to_affine()
    x, y = crypto_pubkey.public_numbers().x, crypto_pubkey.public_numbers().y
    assert umbral_affine == (x, y)


def test_umbral_public_key_equality():
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    as_bytes = bytes(umbral_pub_key)
    assert umbral_pub_key == as_bytes

    reconstructed = UmbralPublicKey.from_bytes(as_bytes)
    assert reconstructed == umbral_pub_key

    assert not umbral_pub_key == b"some whatever bytes"

    another_umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    another_umbral_pub_key = another_umbral_priv_key.get_pubkey()

    assert not umbral_pub_key == another_umbral_pub_key

    # Also not equal to a totally disparate type.
    assert not umbral_pub_key == 47


def test_umbral_public_key_as_dict_key():
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    d = {umbral_pub_key: 19}
    assert d[umbral_pub_key] == 19

    another_umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    another_umbral_pub_key = another_umbral_priv_key.get_pubkey()

    with pytest.raises(KeyError):
        d[another_umbral_pub_key]

    d[another_umbral_pub_key] = False

    assert d[umbral_pub_key] == 19
    d[umbral_pub_key] = 20
    assert d[umbral_pub_key] == 20
    assert d[another_umbral_pub_key] is False