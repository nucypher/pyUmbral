import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


DEM_KEYSIZE = 32
DEM_NONCE_SIZE = 12


class UmbralDEM(object):
    def __init__(self, symm_key: bytes) -> None:
        """
        Initializes an UmbralDEM object. Requires a key to perform
        ChaCha20-Poly1305.
        """
        if len(symm_key) != DEM_KEYSIZE:
            raise ValueError(
                "Invalid key size, must be {} bytes".format(DEM_KEYSIZE)
            )

        self.cipher = ChaCha20Poly1305(symm_key)

    def encrypt(self, data: bytes, authenticated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypts data using ChaCha20-Poly1305 with optional authenticated data.
        """
        nonce = os.urandom(DEM_NONCE_SIZE)
        enc_data = self.cipher.encrypt(nonce, data, authenticated_data)
        # Ciphertext will be a 12 byte nonce, the ciphertext, and a 16 byte tag.
        return nonce + enc_data

    def decrypt(self, ciphertext: bytes, authenticated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypts data using ChaCha20-Poly1305 and validates the provided
        authenticated data.
        """
        nonce = ciphertext[:DEM_NONCE_SIZE]
        ciphertext = ciphertext[DEM_NONCE_SIZE:]
        cleartext = self.cipher.decrypt(nonce, ciphertext, authenticated_data)
        return cleartext
