import pytest
import os

from umbral import GenericError
from umbral.dem import DEM


def test_encrypt_decrypt():

    key = os.urandom(DEM.KEY_SIZE)
    dem = DEM(key)

    plaintext = b'peace at dawn'

    ciphertext0 = dem.encrypt(plaintext)
    ciphertext1 = dem.encrypt(plaintext)

    assert ciphertext0 != plaintext
    assert ciphertext1 != plaintext

    # Ciphertext should be different even with same plaintext.
    assert ciphertext0 != ciphertext1

    # Nonce should be different
    assert ciphertext0[:DEM.NONCE_SIZE] != ciphertext1[:DEM.NONCE_SIZE]

    cleartext0 = dem.decrypt(ciphertext0)
    cleartext1 = dem.decrypt(ciphertext1)

    assert cleartext0 == plaintext
    assert cleartext1 == plaintext


def test_malformed_ciphertext():

    key = os.urandom(DEM.KEY_SIZE)
    dem = DEM(key)

    plaintext = b'peace at dawn'
    ciphertext = dem.encrypt(plaintext)

    # So short it we can tell right away it doesn't even contain a nonce
    with pytest.raises(ValueError, match="The ciphertext must include the nonce"):
        dem.decrypt(ciphertext[:DEM.NONCE_SIZE-1])

    # Too short to contain a tag
    with pytest.raises(ValueError, match="The authentication tag is missing or malformed"):
        dem.decrypt(ciphertext[:DEM.NONCE_SIZE + DEM.TAG_SIZE - 1])

    # Too long
    with pytest.raises(GenericError):
        dem.decrypt(ciphertext + b'abcd')


def test_encrypt_decrypt_associated_data():
    key = os.urandom(32)
    aad = b'secret code 1234'

    dem = DEM(key)

    plaintext = b'peace at dawn'

    ciphertext0 = dem.encrypt(plaintext, authenticated_data=aad)
    ciphertext1 = dem.encrypt(plaintext, authenticated_data=aad)

    assert ciphertext0 != plaintext
    assert ciphertext1 != plaintext

    assert ciphertext0 != ciphertext1

    assert ciphertext0[:DEM.NONCE_SIZE] != ciphertext1[:DEM.NONCE_SIZE]

    cleartext0 = dem.decrypt(ciphertext0, authenticated_data=aad)
    cleartext1 = dem.decrypt(ciphertext1, authenticated_data=aad)

    assert cleartext0 == plaintext
    assert cleartext1 == plaintext

    # Attempt decryption with invalid associated data
    with pytest.raises(GenericError):
        cleartext2 = dem.decrypt(ciphertext0, authenticated_data=b'wrong data')
