from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .serializable import Serializable


class Signature(Serializable):
    """
    Wrapper for ECDSA signatures.
    """

    def __init__(self, r: CurveScalar, s: CurveScalar):
        self.r = r
        self.s = s

    def __repr__(self):
        return f"ECDSA Signature: {bytes(self).hex()[:15]}"

    def verify_digest(self, verifying_key: 'PublicKey', digest: 'Hash') -> bool:
        backend_pk = openssl.point_to_pubkey(CURVE, verifying_key.point()._backend_point)
        signature_algorithm = ECDSA(utils.Prehashed(digest._backend_hash_algorithm))

        message = digest.finalize()
        signature_der_bytes = utils.encode_dss_signature(int(self.r), int(self.s))

        # TODO: Raise error instead of returning boolean
        try:
            backend_pk.verify(signature=signature_der_bytes,
                              data=message,
                              signature_algorithm=signature_algorithm)
        except InvalidSignature:
            return False
        return True

    @classmethod
    def __take__(cls, data):
        (r, s), data = cls.__take_types__(data, CurveScalar, CurveScalar)
        return cls(r, s), data

    def __bytes__(self):
        return bytes(self.r) + bytes(self.s)

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s
