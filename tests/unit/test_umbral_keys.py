"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import os
import pytest
import string

from umbral.config import default_params
from umbral.keys import UmbralPublicKey, UmbralPrivateKey, UmbralKeyingMaterial
from umbral.point import Point


def test_gen_key():
    # Pass in the parameters to test that manual param selection works
    umbral_priv_key = UmbralPrivateKey.gen_key()
    assert type(umbral_priv_key) == UmbralPrivateKey

    umbral_pub_key = umbral_priv_key.get_pubkey()
    assert type(umbral_pub_key) == UmbralPublicKey


def test_derive_key_from_label():
    umbral_keying_material = UmbralKeyingMaterial()

    label = b"my_healthcare_information"

    priv_key1 = umbral_keying_material.derive_privkey_by_label(label)
    assert type(priv_key1) == UmbralPrivateKey

    pub_key1 = priv_key1.get_pubkey()
    assert type(pub_key1) == UmbralPublicKey

    # Check that key derivation is reproducible
    priv_key2 = umbral_keying_material.derive_privkey_by_label(label)
    pub_key2 = priv_key2.get_pubkey()
    assert priv_key1.bn_key == priv_key2.bn_key
    assert pub_key1 == pub_key2

    # A salt can be used too, but of course it affects the derived key
    salt = b"optional, randomly generated salt"
    priv_key3 = umbral_keying_material.derive_privkey_by_label(label, salt=salt)
    assert priv_key3.bn_key != priv_key1.bn_key

    # Different labels on the same master secret create different keys
    label = b"my_tax_information"
    priv_key4 = umbral_keying_material.derive_privkey_by_label(label)
    pub_key4 = priv_key4.get_pubkey()
    assert priv_key1.bn_key != priv_key4.bn_key


def test_private_key_serialization(random_ec_curvebn1):
    priv_key = random_ec_curvebn1
    umbral_key = UmbralPrivateKey(priv_key, default_params())

    encoded_key = umbral_key.to_bytes()

    decoded_key = UmbralPrivateKey.from_bytes(encoded_key)
    assert priv_key == decoded_key.bn_key


def test_private_key_serialization_with_encryption(random_ec_curvebn1):
    priv_key = random_ec_curvebn1
    umbral_key = UmbralPrivateKey(priv_key, default_params())

    insecure_cost = 15  # This is deliberately insecure, just to make the tests faster
    encoded_key = umbral_key.to_bytes(password=b'test', 
                                      _scrypt_cost=insecure_cost)

    decoded_key = UmbralPrivateKey.from_bytes(encoded_key, 
                                              password=b'test', 
                                              _scrypt_cost=insecure_cost)
    assert priv_key == decoded_key.bn_key


def test_public_key_serialization(random_ec_curvebn1):
    umbral_key = UmbralPrivateKey(random_ec_curvebn1, default_params()).get_pubkey()
    pub_point = umbral_key.point_key

    encoded_key = umbral_key.to_bytes()

    decoded_key = UmbralPublicKey.from_bytes(encoded_key)
    assert pub_point == decoded_key.point_key


def test_public_key_to_compressed_bytes(random_ec_curvebn1):
    umbral_key = UmbralPrivateKey(random_ec_curvebn1, default_params()).get_pubkey()
    key_bytes = bytes(umbral_key)
    assert len(key_bytes) == Point.expected_bytes_length(is_compressed=True)


def test_public_key_to_uncompressed_bytes(random_ec_curvebn1):
    umbral_key = UmbralPrivateKey(random_ec_curvebn1, default_params()).get_pubkey()
    key_bytes = umbral_key.to_bytes(is_compressed=False)
    assert len(key_bytes) == Point.expected_bytes_length(is_compressed=False)


def test_key_encoder_decoder(random_ec_curvebn1):
    priv_key = random_ec_curvebn1
    umbral_key = UmbralPrivateKey(priv_key, default_params())

    encoded_key = umbral_key.to_bytes(encoder=base64.urlsafe_b64encode)

    decoded_key = UmbralPrivateKey.from_bytes(encoded_key,
                                              decoder=base64.urlsafe_b64decode)
    assert decoded_key.to_bytes() == umbral_key.to_bytes()


def test_public_key_as_hex(random_ec_curvebn1):
    pubkey = UmbralPrivateKey(random_ec_curvebn1, default_params()).get_pubkey()
    hex_string = pubkey.hex()

    assert set(hex_string).issubset(set(string.hexdigits))
    assert len(hex_string) == 2 * UmbralPublicKey.expected_bytes_length()

    decoded_pubkey = UmbralPublicKey.from_hex(hex_string)

    assert pubkey == decoded_pubkey

    hex_string = pubkey.hex(is_compressed=False)

    assert set(hex_string).issubset(set(string.hexdigits))
    assert len(hex_string) == 2 * UmbralPublicKey.expected_bytes_length(is_compressed=False)

    decoded_pubkey = UmbralPublicKey.from_hex(hex_string)
    assert pubkey == decoded_pubkey


def test_umbral_key_to_cryptography_keys():
    umbral_priv_key = UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    crypto_privkey = umbral_priv_key.to_cryptography_privkey()
    assert int(umbral_priv_key.bn_key) == crypto_privkey.private_numbers().private_value

    crypto_pubkey = umbral_pub_key.to_cryptography_pubkey()
    umbral_affine = umbral_pub_key.point_key.to_affine()
    x, y = crypto_pubkey.public_numbers().x, crypto_pubkey.public_numbers().y
    assert umbral_affine == (x, y)


def test_keying_material_serialization():
    umbral_keying_material = UmbralKeyingMaterial()

    encoded_keying_material = umbral_keying_material.to_bytes()

    decoded_keying_material = UmbralKeyingMaterial.from_bytes(encoded_keying_material)

    label = os.urandom(32)
    privkey_bytes = umbral_keying_material.derive_privkey_by_label(label).to_bytes()
    assert privkey_bytes == decoded_keying_material.derive_privkey_by_label(label).to_bytes()


def test_keying_material_serialization_with_encryption():
    umbral_keying_material = UmbralKeyingMaterial()

    insecure_cost = 15  # This is deliberately insecure, just to make the tests faster
    encoded_keying_material = umbral_keying_material.to_bytes(password=b'test',
                                                              _scrypt_cost=insecure_cost)

    decoded_keying_material = UmbralKeyingMaterial.from_bytes(encoded_keying_material,
                                                              password=b'test',
                                                              _scrypt_cost=insecure_cost)

    label = os.urandom(32)
    privkey_bytes = umbral_keying_material.derive_privkey_by_label(label).to_bytes()
    assert privkey_bytes == decoded_keying_material.derive_privkey_by_label(label).to_bytes()


def test_umbral_public_key_equality():
    umbral_priv_key = UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    as_bytes = bytes(umbral_pub_key)
    assert umbral_pub_key == as_bytes

    reconstructed = UmbralPublicKey.from_bytes(as_bytes)
    assert reconstructed == umbral_pub_key

    assert not umbral_pub_key == b"some whatever bytes"

    another_umbral_priv_key = UmbralPrivateKey.gen_key()
    another_umbral_pub_key = another_umbral_priv_key.get_pubkey()

    assert not umbral_pub_key == another_umbral_pub_key

    # Also not equal to a totally disparate type.
    assert not umbral_pub_key == 107


def test_umbral_public_key_as_dict_key():
    umbral_priv_key = UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    d = {umbral_pub_key: 19}
    assert d[umbral_pub_key] == 19

    another_umbral_priv_key = UmbralPrivateKey.gen_key()
    another_umbral_pub_key = another_umbral_priv_key.get_pubkey()

    with pytest.raises(KeyError):
        _ = d[another_umbral_pub_key]

    d[another_umbral_pub_key] = False

    assert d[umbral_pub_key] == 19
    d[umbral_pub_key] = 20
    assert d[umbral_pub_key] == 20
    assert d[another_umbral_pub_key] is False
