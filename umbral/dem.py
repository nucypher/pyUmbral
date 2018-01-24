import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class UmbralDEM(object):
    def __init__(self, symm_key: bytes):
        """
        Initializes an UmbralDEM object. Requires a key to perform
        ChaCha20-Poly1305.
        """
        if len(symm_key) != 32:
            raise ValueError(
                "Invalid key size, must be {} bytes".format(SecretBox.KEY_SIZE)
            )

        self.cipher = ChaCha20Poly1305(symm_key)

    def encrypt(self, data: bytes, authenticated_data: bytes=None):
        """
        Encrypts data using ChaCha20-Poly1305 with optional authenticated data.
        """
        nonce = os.urandom(12)
        enc_data = self.cipher.encrypt(nonce, data, authenticated_data)
        return nonce + enc_data

    def decrypt(self, enc_data: bytes, authenticated_data: bytes=None):
        """
        Decrypts data using ChaCha20-Poly1305 and validates the provided
        authenticated data.
        """
        nonce = enc_data[:12]
        ciphertext = enc_data[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, authenticated_data)
        return plaintext
