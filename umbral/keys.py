from typing import TYPE_CHECKING, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey, _EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .curve_point import CurvePoint
from .dem import DEM
from .serializable import Serializable

if TYPE_CHECKING: # pragma: no cover
    from .hashing import Hash


class SecretKey(Serializable):

    __SERIALIZATION_INFO = b"SECRET_KEY"

    def __init__(self, scalar_key: CurveScalar):
        self._scalar_key = scalar_key

    @classmethod
    def random(cls) -> 'SecretKey':
        """
        Generates a secret key and returns it.
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

    def to_cryptography_privkey(self) -> _EllipticCurvePrivateKey:
        """
        Returns a cryptography.io EllipticCurvePrivateKey from the Umbral key.
        """
        ec_key = backend._lib.EC_KEY_new()
        backend.openssl_assert(ec_key != backend._ffi.NULL)
        ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

        set_group_result = backend._lib.EC_KEY_set_group(ec_key, CURVE.ec_group)
        backend.openssl_assert(set_group_result == 1)

        set_privkey_result = backend._lib.EC_KEY_set_private_key(
            ec_key, self._scalar_key._backend_bignum
        )
        backend.openssl_assert(set_privkey_result == 1)

        # Get public key
        point = openssl._get_new_EC_POINT(CURVE)
        with backend._tmp_bn_ctx() as bn_ctx:
            mult_result = backend._lib.EC_POINT_mul(
                CURVE.ec_group, point, self._scalar_key._backend_bignum,
                backend._ffi.NULL, backend._ffi.NULL, bn_ctx
            )
            backend.openssl_assert(mult_result == 1)

        set_pubkey_result = backend._lib.EC_KEY_set_public_key(ec_key, point)
        backend.openssl_assert(set_pubkey_result == 1)

        evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
        return _EllipticCurvePrivateKey(backend, ec_key, evp_pkey)

    def sign_digest(self, digest: 'Hash', backend_hash_algorithm) -> 'Signature':

        signature_algorithm = ECDSA(utils.Prehashed(backend_hash_algorithm()))
        message = digest.finalize()

        cpk = self.to_cryptography_privkey()
        signature_der_bytes = cpk.sign(message, signature_algorithm)
        r, s = utils.decode_dss_signature(signature_der_bytes)

        # Normalize s
        # s is public, so no constant-timeness required here
        order = backend._bn_to_int(CURVE.order)
        if s > (order >> 1):
            s = order - s

        return Signature(CurveScalar.from_int(r), CurveScalar.from_int(s))


class Signature(Serializable):
    """
    Wrapper for ECDSA signatures.
    We store signatures as r and s; this class allows interoperation
    between (r, s) and DER formatting.
    """

    def __init__(self, r: CurveScalar, s: CurveScalar):
        self.r = r
        self.s = s

    def __repr__(self):
        return f"ECDSA Signature: {bytes(self).hex()[:15]}"

    def verify_digest(self, verifying_key: 'PublicKey', digest: 'Hash', backend_hash_algorithm) -> bool:
        cryptography_pub_key = verifying_key.to_cryptography_pubkey()
        signature_algorithm = ECDSA(utils.Prehashed(backend_hash_algorithm()))
        message = digest.finalize()
        signature_der_bytes = utils.encode_dss_signature(int(self.r), int(self.s))

        # TODO: Raise error instead of returning boolean
        try:
            cryptography_pub_key.verify(signature=signature_der_bytes,
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

    def __init__(self, point_key: CurvePoint):
        self._point_key = point_key

    def point(self):
        return self._point_key

    @classmethod
    def from_secret_key(cls, sk: SecretKey) -> 'PublicKey':
        return cls(CurvePoint.generator() * sk.secret_scalar())

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['PublicKey', bytes]:
        (point_key,), data = cls.__take_types__(data, CurvePoint)
        return cls(point_key), data

    def __bytes__(self) -> bytes:
        return bytes(self._point_key)

    def to_cryptography_pubkey(self) -> _EllipticCurvePublicKey:
        """
        Returns a cryptography.io EllipticCurvePublicKey from the Umbral key.
        """
        ec_key = backend._lib.EC_KEY_new()
        backend.openssl_assert(ec_key != backend._ffi.NULL)
        ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

        set_group_result = backend._lib.EC_KEY_set_group(ec_key, CURVE.ec_group)
        backend.openssl_assert(set_group_result == 1)

        set_pubkey_result = backend._lib.EC_KEY_set_public_key(
            ec_key, self._point_key._backend_point
        )
        backend.openssl_assert(set_pubkey_result == 1)

        evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
        return _EllipticCurvePublicKey(backend, ec_key, evp_pkey)

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    def __eq__(self, other):
        return self._point_key == other._point_key

    def __hash__(self) -> int:
        return hash((self.__class__, bytes(self)))
