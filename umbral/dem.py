import os
from typing import Optional

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes

from nacl.bindings.crypto_aead import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES as XCHACHA_KEY_SIZE,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as XCHACHA_NONCE_SIZE,
    )


def kdf(data: bytes,
        key_length: int,
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
        ) -> bytes:

    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=key_length,
                salt=salt,
                info=info,
                backend=backend)
    return hkdf.derive(data)


class DEM:

    KEY_SIZE = XCHACHA_KEY_SIZE
    NONCE_SIZE = XCHACHA_NONCE_SIZE

    def __init__(self,
                 key_material: bytes,
                 salt: Optional[bytes] = None,
                 info: Optional[bytes] = None,
                 ):
        self._key = kdf(key_material, self.KEY_SIZE, salt, info)

    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"The nonce must be exactly {self.NONCE_SIZE} bytes long")

        ciphertext = xchacha_encrypt(plaintext, b"", nonce, self._key)
        return nonce + ciphertext

    def decrypt(self, nonce_and_ciphertext: bytes) -> bytes:

        if len(nonce_and_ciphertext) < self.NONCE_SIZE:
            raise ValueError(f"The ciphertext must include the nonce")

        nonce = nonce_and_ciphertext[:self.NONCE_SIZE]
        ciphertext = nonce_and_ciphertext[self.NONCE_SIZE:]

        # TODO: replace `nacl.exceptions.CryptoError` with our error?
        return xchacha_decrypt(ciphertext, b"", nonce, self._key)
