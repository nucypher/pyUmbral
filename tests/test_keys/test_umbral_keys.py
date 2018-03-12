from umbral import pre, keys


def test_gen_key():
    # Pass in the parameters to test that manual param selection works
    umbral_priv_key = keys.UmbralPrivateKey.gen_key()
    assert type(umbral_priv_key) == keys.UmbralPrivateKey

    umbral_pub_key = umbral_priv_key.get_pubkey()
    assert type(umbral_pub_key) == keys.UmbralPublicKey


def test_private_key_serialization():
    priv_key = pre.gen_priv()
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.to_bytes()

    decoded_key = keys.UmbralPrivateKey.from_bytes(encoded_key)
    assert priv_key == decoded_key.bn_key


def test_private_key_serialization_with_encryption():
    priv_key = pre.gen_priv()
    umbral_key = keys.UmbralPrivateKey(priv_key)

    encoded_key = umbral_key.to_bytes(password=b'test')

    decoded_key = keys.UmbralPrivateKey.from_bytes(encoded_key, password=b'test')
    assert priv_key == decoded_key.bn_key


def test_public_key_serialization():
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    umbral_key = keys.UmbralPublicKey(pub_key)

    encoded_key = umbral_key.to_bytes()

    decoded_key = keys.UmbralPublicKey.from_bytes(encoded_key)
    assert pub_key == decoded_key.point_key


def test_public_key_to_bytes():
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

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
