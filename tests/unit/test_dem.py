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

import pytest
import os

from umbral.dem import UmbralDEM, DEM_KEYSIZE, DEM_NONCE_SIZE
from cryptography.exceptions import InvalidTag


def test_encrypt_decrypt():
    key = os.urandom(32)

    dem = UmbralDEM(key)

    plaintext = b'peace at dawn'

    ciphertext0 = dem.encrypt(plaintext)
    ciphertext1 = dem.encrypt(plaintext)

    assert ciphertext0 != plaintext
    assert ciphertext1 != plaintext

    # Ciphertext should be different even with same plaintext.
    assert ciphertext0 != ciphertext1

    # Nonce should be different
    assert ciphertext0[:DEM_NONCE_SIZE] != ciphertext1[:DEM_NONCE_SIZE]

    cleartext0 = dem.decrypt(ciphertext0)
    cleartext1 = dem.decrypt(ciphertext1)

    assert cleartext0 == plaintext
    assert cleartext1 == plaintext


def test_encrypt_decrypt_associated_data():
    key = os.urandom(32)
    aad = b'secret code 1234'

    dem = UmbralDEM(key)

    plaintext = b'peace at dawn'

    ciphertext0 = dem.encrypt(plaintext, authenticated_data=aad)
    ciphertext1 = dem.encrypt(plaintext, authenticated_data=aad)

    assert ciphertext0 != plaintext
    assert ciphertext1 != plaintext

    assert ciphertext0 != ciphertext1

    assert ciphertext0[:DEM_NONCE_SIZE] != ciphertext1[:DEM_NONCE_SIZE]

    cleartext0 = dem.decrypt(ciphertext0, authenticated_data=aad)
    cleartext1 = dem.decrypt(ciphertext1, authenticated_data=aad)

    assert cleartext0 == plaintext
    assert cleartext1 == plaintext

    # Attempt decryption with invalid associated data
    with pytest.raises(InvalidTag):
        cleartext2 = dem.decrypt(ciphertext0, authenticated_data=b'wrong data')
