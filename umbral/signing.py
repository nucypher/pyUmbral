from cryptography.exceptions import InvalidSignature

from umbral.config import default_curve
from umbral.keys import UmbralPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from umbral.keys import UmbralPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from umbral.utils import get_curve_keysize_bytes

_BLAKE2B = hashes.BLAKE2b(64)


class Signature(object):
    """
    The Signature object allows signatures to be made and verified.
    """

    def __init__(self, r: int, s: int):
        #  TODO: Sanity check for proper r and s.
        self.r = r
        self.s = s

    def __repr__(self):
        return "ECDSA Signature: {}".format(bytes(self).hex()[:15])

    @classmethod
    def get_size(cls, curve: ec.EllipticCurve = None):
        curve = curve if curve is not None else default_curve()
        return get_curve_keysize_bytes(curve) * 2

    def verify(self, message: bytes, pubkey: UmbralPublicKey) -> bool:
        """
        Verifies that a message's signature was valid.

        :param message: The message to verify
        :param pubkey: UmbralPublicKey of the signer

        :return: True if valid, False if invalid
        """
        cryptography_pub_key = pubkey.to_cryptography_pubkey()

        try:
            cryptography_pub_key.verify(
                self._der_encoded_bytes(),
                message,
                ec.ECDSA(_BLAKE2B)
            )
        except InvalidSignature:
            return False
        return True

    @classmethod
    def from_bytes(cls, signature_as_bytes, der_encoded=False):
        # TODO: Change the int literals to variables which account for the order of the curve.
        if der_encoded:
            r, s = decode_dss_signature(signature_as_bytes)
        else:
            if not len(signature_as_bytes) == 64:
                raise ValueError("Looking for exactly 64 bytes if you call from_bytes with der_encoded=False.")
            else:
                r = int.from_bytes(signature_as_bytes[:32], "big")
                s = int.from_bytes(signature_as_bytes[32:], "big")
        return cls(r, s)

    def _der_encoded_bytes(self):
        return encode_dss_signature(self.r, self.s)

    def __bytes__(self):
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big")

    def __len__(self):
        return len(bytes(self))

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __eq__(self, other):
        # TODO: Consider constant time
        return bytes(self) == bytes(other) or self._der_encoded_bytes() == other


class Signer:

    def __init__(self, private_key: UmbralPrivateKey):
        self.__cryptography_private_key = private_key.to_cryptography_privkey()

    def __call__(self, message):
        """
         Accepts a hashed message and signs it with the private key given.

         :param message: Message to hash and sign
         :return: signature
         """
        signature_der_bytes = self.__cryptography_private_key.sign(message, ec.ECDSA(_BLAKE2B))
        return Signature.from_bytes(signature_der_bytes, der_encoded=True)
