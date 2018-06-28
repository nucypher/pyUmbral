import hmac

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes

from umbral.config import default_curve
from umbral.curve import Curve
from umbral.keys import UmbralPublicKey, UmbralPrivateKey
from umbral.curvebn import CurveBN
from umbral.utils import get_field_order_size_in_bytes

_BLAKE2B = hashes.BLAKE2b(64)


class Signature:
    """
    We store signatures as r and s; this class allows interoperation
    between (r, s) and DER formatting.
    """

    def __init__(self, r: CurveBN, s: CurveBN):
        self.r = r
        self.s = s

    def __repr__(self):
        return "ECDSA Signature: {}".format(bytes(self).hex()[:15])

    @classmethod
    def expected_bytes_length(cls, curve: Curve = None):
        curve = curve if curve is not None else default_curve()
        return get_field_order_size_in_bytes(curve) * 2

    def verify(self, message: bytes, verifying_key: UmbralPublicKey) -> bool:
        """
        Verifies that a message's signature was valid.

        :param message: The message to verify
        :param pubkey: UmbralPublicKey of the signer

        :return: True if valid, False if invalid
        """
        cryptography_pub_key = verifying_key.to_cryptography_pubkey()

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
    def from_bytes(cls, signature_as_bytes, der_encoded=False, curve: Curve = None):
        curve = curve if curve is not None else default_curve()
        if der_encoded:
            r, s = decode_dss_signature(signature_as_bytes)
        else:
            expected_len = cls.expected_bytes_length(curve)
            if not len(signature_as_bytes) == expected_len:
                raise ValueError("Looking for exactly {} bytes if you call from_bytes \
                    with der_encoded=False and curve={}.".format(expected_len, curve))
            else:
                r = int.from_bytes(signature_as_bytes[:(expected_len//2)], "big")
                s = int.from_bytes(signature_as_bytes[(expected_len//2):], "big")
        
        return cls(CurveBN.from_int(r, curve), CurveBN.from_int(s, curve))

    def _der_encoded_bytes(self):
        return encode_dss_signature(int(self.r), int(self.s))

    def __bytes__(self):
        return self.r.to_bytes() + self.s.to_bytes()

    def __len__(self):
        return len(bytes(self))

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __eq__(self, other):
        simple_bytes_match = hmac.compare_digest(bytes(self), bytes(other))
        der_encoded_match = hmac.compare_digest(self._der_encoded_bytes(), bytes(other))
        return simple_bytes_match or der_encoded_match


class Signer:

    def __init__(self, private_key: UmbralPrivateKey):
        self.__cryptography_private_key = private_key.to_cryptography_privkey()
        self._curve = private_key.params.curve

    def __call__(self, message):
        """
         Signs the message with this instance's private key.

         :param message: Message to hash and sign
         :return: signature
         """
        signature_der_bytes = self.__cryptography_private_key.sign(message, ec.ECDSA(_BLAKE2B))
        return Signature.from_bytes(signature_der_bytes, der_encoded=True, curve=self._curve)
