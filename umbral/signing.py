from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .hashing import Hash
from .keys import SecretKey, PublicKey
from .serializable import Serializable, Deserializable


def digest_for_signing(message: bytes) -> Hash:
    # Not using a DST here to make life easier for third-party verifiers
    digest = Hash()
    digest.update(message)
    return digest


class Signer:
    """
    An object possessing the capability to create signatures.
    For safety reasons serialization is prohibited.
    """

    def __init__(self, secret_key: SecretKey):
        self.__secret_key = secret_key

    def sign_digest(self, digest: Hash) -> 'Signature':

        secret_bn = self.__secret_key.secret_scalar()._backend_bignum
        r_int, s_int = openssl.ecdsa_sign(curve=CURVE,
                                          secret_bn=secret_bn,
                                          prehashed_message=digest.finalize(),
                                          hash_algorithm=digest._backend_hash_algorithm)

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
        return self.__secret_key.public_key()

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise RuntimeError(f"{self.__class__.__name__} objects do not support hashing")

    def __bytes__(self):
        raise RuntimeError(f"{self.__class__.__name__} objects do not support serialization")


class Signature(Serializable, Deserializable):
    """
    Wrapper for ECDSA signatures.
    """

    def __init__(self, r: CurveScalar, s: CurveScalar):
        self.r = r
        self.s = s

    def verify_digest(self, verifying_key: PublicKey, digest: Hash) -> bool:
        return openssl.ecdsa_verify(curve=CURVE,
                                    sig_r=int(self.r),
                                    sig_s=int(self.s),
                                    public_point=verifying_key.point()._backend_point,
                                    prehashed_message=digest.finalize(),
                                    hash_algorithm=digest._backend_hash_algorithm)

    def verify(self, verifying_key: PublicKey, message: bytes) -> bool:
        """
        Returns ``True`` if the ``message`` was signed by someone possessing the secret counterpart
        to ``verifying_key``.
        """
        digest = digest_for_signing(message)
        return self.verify_digest(verifying_key, digest)

    @classmethod
    def serialized_size(cls):
        return CurveScalar.serialized_size() * 2

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        return cls(*cls._split(data, CurveScalar, CurveScalar))

    def __bytes__(self):
        return bytes(self.r) + bytes(self.s)

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s

    def __hash__(self) -> int:
        return hash((self.__class__, bytes(self)))
