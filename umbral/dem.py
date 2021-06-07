import os
from typing import Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import nacl
from nacl.bindings.crypto_aead import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES as XCHACHA_KEY_SIZE,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as XCHACHA_NONCE_SIZE,
    crypto_aead_xchacha20poly1305_ietf_ABYTES as XCHACHA_TAG_SIZE,
    )

from . import openssl


def kdf(data: bytes,
        key_length: int,
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
        ) -> bytes:

    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                info=info,
                backend=openssl.backend)
    return hkdf.derive(data)


class DEM:

    KEY_SIZE = XCHACHA_KEY_SIZE
    NONCE_SIZE = XCHACHA_NONCE_SIZE
    TAG_SIZE = XCHACHA_TAG_SIZE

    def __init__(self,
                 key_material: bytes,
                 salt: Optional[bytes] = None,
                 info: Optional[bytes] = None,
                 ):
        self._key = kdf(key_material, self.KEY_SIZE, salt, info)

    def encrypt(self, plaintext: bytes, authenticated_data: bytes = b"") -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = xchacha_encrypt(plaintext, authenticated_data, nonce, self._key)
        return nonce + ciphertext

    def decrypt(self, nonce_and_ciphertext: bytes, authenticated_data: bytes = b"") -> bytes:

        if len(nonce_and_ciphertext) < self.NONCE_SIZE:
            raise ValueError("The ciphertext must include the nonce")

        nonce = nonce_and_ciphertext[:self.NONCE_SIZE]
        ciphertext = nonce_and_ciphertext[self.NONCE_SIZE:]

        # Prevent an out of bounds error deep in NaCl
        if len(ciphertext) < self.TAG_SIZE:
            raise ValueError("The authentication tag is missing or malformed")

        try:
            return xchacha_decrypt(ciphertext, authenticated_data, nonce, self._key)
        except nacl.exceptions.CryptoError as e:
            raise ValueError("Decryption of ciphertext failed: "
                             "either someone tampered with the ciphertext or "
                             "you are using an incorrect decryption key.") from e
