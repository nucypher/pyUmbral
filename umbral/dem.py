from nacl.secret import SecretBox


class UmbralDEM(object):
    def __init__(self, symm_key: bytes):
        """
        Initializes an UmbralDEM object. Requires a key to perform
        Salsa20-Poly1305.
        """
        self.KEYSIZE = SecretBox.KEY_SIZE

        if len(symm_key) != self.KEYSIZE
            raise ValueError(
                "Invalid key size, must be {} bytes".format(SecretBox.KEY_SIZE)
            )

        self.cipher = SecretBox(symm_key)

    def encrypt(self, data: bytes):
        """
        Encrypts data using NaCl's Salsa20-Poly1305 secret box symmetric cipher.
        """
        enc_data = self.cipher.encrypt(data)
        return enc_data

    def decrypt(self, enc_data: bytes):
        """
        Decrypts data using NaCl's Salsa20-Poly1305 secret box symmetric cipher.
        """
        plaintext = self.cipher.decrypt(enc_data)
        return plaintext
