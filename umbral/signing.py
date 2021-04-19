from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .hashing import Hash
from .keys import SecretKey, PublicKey
from .serializable import Serializable


def digest_for_signing(message: bytes) -> Hash:
    digest = Hash(b'SIGNER')
    digest.update(message)
    return digest


class Signer:
    """
    An object possessing the capability to create signatures.
    For safety reasons serialization is prohibited.
    """

    def __init__(self, secret_key: SecretKey):
        self.__secret_key = secret_key

    def sign_digest(self, digest: 'Hash') -> 'Signature':

        signature_algorithm = ECDSA(utils.Prehashed(digest._backend_hash_algorithm))
        message = digest.finalize()

        backend_sk = openssl.bn_to_privkey(CURVE, self.__secret_key.secret_scalar()._backend_bignum)
        signature_der_bytes = backend_sk.sign(message, signature_algorithm)
        r_int, s_int = utils.decode_dss_signature(signature_der_bytes)

        # Normalize s. This is a non-malleability measure, which OpenSSL doesn't do.
        # See Bitcoin's BIP-0062 for more details:
        # https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures

        # s is public, so no constant-timeness required here
        if s_int > (CURVE.order >> 1):
            s_int = CURVE.order - s_int

        # Already normalized, don't waste time
        r = CurveScalar.from_int(r_int, check_normalization=False)
        s = CurveScalar.from_int(s_int, check_normalization=False)

        return Signature(r, s)

    def sign(self, message: bytes) -> 'Signature':
        """
        Hashes and signs the message.
        """
        return self.sign_digest(digest_for_signing(message))

    def verifying_key(self) -> PublicKey:
        """
        Returns the public verification key corresponding to the secret key used for signing.
        """
        return PublicKey.from_secret_key(self.__secret_key)

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise RuntimeError(f"{self.__class__.__name__} objects do not support hashing")

    def __bytes__(self):
        raise RuntimeError(f"{self.__class__.__name__} objects do not support serialization")


class Signature(Serializable):
    """
    Wrapper for ECDSA signatures.
    """

    def __init__(self, r: CurveScalar, s: CurveScalar):
        self.r = r
        self.s = s

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

    def verify(self, verifying_key: PublicKey, message: bytes) -> bool:
        """
        Returns ``True`` if the ``message`` was signed by someone possessing the secret counterpart
        to ``verifying_key``.
        """
        digest = digest_for_signing(message)
        return self.verify_digest(verifying_key, digest)

    @classmethod
    def __take__(cls, data):
        (r, s), data = cls.__take_types__(data, CurveScalar, CurveScalar)
        return cls(r, s), data

    def __bytes__(self):
        return bytes(self.r) + bytes(self.s)

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s

    def __hash__(self) -> int:
        return hash((self.__class__, bytes(self)))
