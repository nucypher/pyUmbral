import os
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from nacl.secret import SecretBox
from umbral.point import Point, BigNum


class UmbralPrivateKey(object):
    def __init__(self, bn_key: BigNum):
        """
        Initializes an Umbral private key.
        """
        self.bn_key = bn_key

    @classmethod
    def gen_key(cls, params):
        """
        Generates a private key and returns it.
        """
        bn_key = BigNum.gen_rand(params.curve)
        return cls(bn_key)

    @classmethod
    def load_key(cls, key_data: str, params,
                 password: bytes=None, _scrypt_cost: int=20):
        """
        Loads an Umbral private key from a urlsafe base64 encoded string.
        Optionally, if a password is provided it will decrypt the key using
        nacl's Salsa20-Poly1305 and Scrypt key derivation.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. Unless you changed this when you called `save_key`, you should
        not change it here. It is NOT recommended to change the `_scrypt_cost`
        value unless you know what you're doing.
        """
        key_bytes = base64.urlsafe_b64decode(key_data)

        if password:
            salt = key_bytes[-16:]
            key_bytes = key_bytes[:-16]

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            key_bytes = SecretBox(key).decrypt(key_bytes)

        bn_key = BigNum.from_bytes(key_bytes, params.curve)
        return cls(bn_key)

    def save_key(self, password: bytes=None, _scrypt_cost: int=20):
        """
        Returns an Umbral private key as a urlsafe base64 encoded string with
        optional symmetric encryption via nacl's Salsa20-Poly1305 and Scrypt
        key derivation. If a password is provided, the user must encode it to
        bytes.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. It is NOT recommended to change the `_scrypt_cost` value unless
        you know what you are doing.
        """
        umbral_priv_key = self.bn_key.to_bytes()

        if password:
            salt = os.urandom(16)

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            umbral_priv_key = SecretBox(key).encrypt(umbral_priv_key)
            umbral_priv_key += salt

        encoded_key = base64.urlsafe_b64encode(umbral_priv_key)
        return encoded_key

    def get_pub_key(self, params):
        """
        Calculates and returns the public key of the private key.
        """
        return UmbralPublicKey(self.bn_key * params.g)


class UmbralPublicKey(object):
    def __init__(self, point_key):
        """
        Initializes an Umbral public key.
        """
        self.point_key = point_key

    @classmethod
    def load_key(cls, key_data: str, params):
        """
        Loads an Umbral public key from a urlsafe base64 encoded string.
        """
        key_bytes = base64.urlsafe_b64decode(key_data)

        point_key = Point.from_bytes(key_bytes, params.curve)
        return cls(point_key)

    def save_key(self):
        """
        Returns an Umbral public key as a urlsafe base64 encoded string.
        """
        umbral_pub_key = self.point_key.to_bytes()

        encoded_key = base64.urlsafe_b64encode(umbral_pub_key)
        return encoded_key
