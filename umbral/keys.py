import os
from typing import TYPE_CHECKING, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .curve_point import CurvePoint
from .dem import kdf
from .serializable import Serializable

if TYPE_CHECKING: # pragma: no cover
    from .hashing import Hash


class SecretKey(Serializable):
    """
    Umbral secret (private) key.
    """

    __SERIALIZATION_INFO = b"SECRET_KEY"

    def __init__(self, scalar_key: CurveScalar):
        self._scalar_key = scalar_key

    @classmethod
    def random(cls) -> 'SecretKey':
        """
        Generates a random secret key and returns it.
        """
        return cls(CurveScalar.random_nonzero())

    def __eq__(self, other):
        return self._scalar_key == other._scalar_key

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise NotImplementedError("Hashing secret objects is insecure")

    def secret_scalar(self):
        return self._scalar_key

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['SecretKey', bytes]:
        (scalar_key,), data = cls.__take_types__(data, CurveScalar)
        return cls(scalar_key), data

    def __bytes__(self) -> bytes:
        return bytes(self._scalar_key)

    def sign_digest(self, digest: 'Hash') -> 'Signature':

        signature_algorithm = ECDSA(utils.Prehashed(digest._backend_hash_algorithm))
        message = digest.finalize()

        backend_sk = openssl.bn_to_privkey(CURVE, self._scalar_key._backend_bignum)
        signature_der_bytes = backend_sk.sign(message, signature_algorithm)
        r_int, s_int = utils.decode_dss_signature(signature_der_bytes)

        # Normalize s
        # s is public, so no constant-timeness required here
        if s_int > (CURVE.order >> 1):
            s_int = CURVE.order - s_int

        # Already normalized, don't waste time
        r = CurveScalar.from_int(r_int, check_normalization=False)
        s = CurveScalar.from_int(s_int, check_normalization=False)

        return Signature(r, s)


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


class PublicKey(Serializable):
    """
    Umbral public key.
    """

    def __init__(self, point_key: CurvePoint):
        self._point_key = point_key

    def point(self):
        return self._point_key

    @classmethod
    def from_secret_key(cls, sk: SecretKey) -> 'PublicKey':
        """
        Creates the public key corresponding to the given secret key.
        """
        return cls(CurvePoint.generator() * sk.secret_scalar())

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['PublicKey', bytes]:
        (point_key,), data = cls.__take_types__(data, CurvePoint)
        return cls(point_key), data

    def __bytes__(self) -> bytes:
        return bytes(self._point_key)

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    def __eq__(self, other):
        return self._point_key == other._point_key

    def __hash__(self) -> int:
        return hash((self.__class__, bytes(self)))


class SecretKeyFactory(Serializable):
    """
    This class handles keyring material for Umbral, by allowing deterministic
    derivation of :py:class:`SecretKey` objects based on labels.

    Don't use this key material directly as a key.
    """

    _KEY_SEED_SIZE = 64
    _DERIVED_KEY_SIZE = 64

    def __init__(self, key_seed: bytes):
        self.__key_seed = key_seed

    @classmethod
    def random(cls) -> 'SecretKeyFactory':
        """
        Creates a random factory.
        """
        return cls(os.urandom(cls._KEY_SEED_SIZE))

    def secret_key_by_label(self, label: bytes) -> SecretKey:
        """
        Creates a :py:class:`SecretKey` from the given label.
        """
        tag = b"KEY_DERIVATION/" + label
        key = kdf(self.__key_seed, self._DERIVED_KEY_SIZE, info=tag)

        from .hashing import Hash
        digest = Hash(tag)
        digest.update(key)
        scalar_key = CurveScalar.from_digest(digest)

        return SecretKey(scalar_key)

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['SecretKeyFactory', bytes]:
        key_seed, data = cls.__take_bytes__(data, cls._KEY_SEED_SIZE)
        return cls(key_seed), data

    def __bytes__(self) -> bytes:
        return bytes(self.__key_seed)

    def __str__(self):
        return f"{self.__class__.__name__}:..."

    def __hash__(self):
        raise NotImplementedError("Hashing secret objects is insecure")
