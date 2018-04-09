from umbral import pre, keys
from umbral.config import default_params

def test_gen_key():
    # Pass in the parameters to test that manual param selection works
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    assert type(umbral_priv_key) == keys.UmbralPrivateKey

    umbral_pub_key = umbral_priv_key.get_pubkey()
    assert type(umbral_pub_key) == keys.UmbralPublicKey

def test_derive_key_from_label():
    master_secret = b"random master secret"
    label = b"my_healthcare_information"

    priv_key1 = keys.UmbralPrivateKey.derive_key_from_label(master_secret, label)
    assert type(priv_key1) == keys.UmbralPrivateKey

    pub_key1 = priv_key1.get_pubkey()
    assert type(pub_key1) == keys.UmbralPublicKey


    priv_key2 = keys.UmbralPrivateKey.derive_key_from_label(master_secret, label)
    pub_key2 = priv_key2.get_pubkey()
    assert priv_key1.bn_key == priv_key2.bn_key
    assert pub_key1 == pub_key2

    # A salt can be used too, but of course it affects the derived key
    salt = b"optional, randomly generated salt"
    priv_key3 = keys.UmbralPrivateKey.derive_key_from_label(master_secret, label, salt=salt)
    assert priv_key3.bn_key != priv_key1.bn_key

    # Different labels on the same master secret create different keys
    label = b"my_tax_information"
    priv_key4 = keys.UmbralPrivateKey.derive_key_from_label(master_secret, label)
    pub_key4 = priv_key4.get_pubkey()
    assert priv_key1.bn_key != priv_key4.bn_key

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


def test_umbral_key_to_cryptography_keys():
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    umbral_pub_key = umbral_priv_key.get_pubkey()

    crypto_privkey = umbral_priv_key.to_cryptography_privkey()
    assert int(umbral_priv_key.bn_key) == crypto_privkey.private_numbers().private_value

    crypto_pubkey = umbral_pub_key.to_cryptography_pubkey()
    umbral_affine = umbral_pub_key.point_key.to_affine()
    x, y = crypto_pubkey.public_numbers().x, crypto_pubkey.public_numbers().y
    assert umbral_affine == (x, y)
