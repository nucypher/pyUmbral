import base64

from cryptography.hazmat.primitives.asymmetric import ec
from umbral.umbral import UmbralParameters
from umbral.point import Point, BigNum


class UmbralPrivateKey(object):
    def __init__(self, bn_key: BigNum):
        """
        Initializes an Umbral private key.
        """
        self.bn_key = bn_key

    @classmethod
    def load_key(cls, key_data: str, params: UmbralParameters):
        """
        Loads an Umbral private key from a urlsafe base64 encoded string.
        """
        key_bytes = base64.urlsafe_b64decode(key_data)

        bn_key = BigNum.from_bytes(key_bytes, params.curve)
        return cls(bn_key)


class UmbralPublicKey(object):
    def __init__(self, point_key):
        """
        Initializes an Umbral public key.
        """
        self.point_key = point_key

    @classmethod
    def load_key(cls, key_data: str, params: UmbralParameters):
        """
        Loads an Umbral public key from a urlsafe base64 encoded string.
        """
        key_bytes = base64.urlsafe_b64decode(key_data)

        point_key = Point.from_bytes(key_bytes, params.curve)
        return cls(point_key)
