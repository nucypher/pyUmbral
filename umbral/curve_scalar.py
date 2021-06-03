from typing import TYPE_CHECKING, Union, Tuple

from . import openssl
from .curve import CURVE
from .serializable import Serializable, Deserializable
if TYPE_CHECKING: # pragma: no cover
    from .hashing import Hash


class CurveScalar(Serializable, Deserializable):
    """
    Represents an OpenSSL Bignum modulo the order of a curve. Some of these
    operations will only work with prime numbers.

    By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
    constant time operations.
    """

    def __init__(self, backend_bignum):
        self._backend_bignum = backend_bignum

    @classmethod
    def random_nonzero(cls) -> 'CurveScalar':
        """
        Returns a CurveScalar object with a cryptographically secure OpenSSL BIGNUM.
        """
        return cls(openssl.bn_random_nonzero(CURVE.bn_order))

    @classmethod
    def from_int(cls, num: int, check_normalization: bool = True) -> 'CurveScalar':
        """
        Returns a CurveScalar object from a given integer on a curve.
        """
        modulus = CURVE.bn_order if check_normalization else None
        conv_bn = openssl.bn_from_int(num, check_modulus=modulus)
        return cls(conv_bn)

    @classmethod
    def from_digest(cls, digest: 'Hash') -> 'CurveScalar':
        # TODO (#39): this is used in Umbral scheme itself,
        # and needs to be able to return a guaranteed nonzero scalar.
        # Currently just matching what we have in rust-umbral
        # (taking bytes modulo curve order).
        # Can produce zeros!
        return cls(openssl.bn_from_bytes(digest.finalize(), apply_modulus=CURVE.bn_order))

    @classmethod
    def serialized_size(cls):
        return CURVE.scalar_size

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        return cls(openssl.bn_from_bytes(data, check_modulus=CURVE.bn_order))

    def __bytes__(self) -> bytes:
        """
        Returns the CurveScalar as bytes.
        """
        return openssl.bn_to_bytes(self._backend_bignum, CURVE.scalar_size)

    def __int__(self) -> int:
        """
        Converts the CurveScalar to a Python int.
        """
        return openssl.bn_to_int(self._backend_bignum)

    def __eq__(self, other) -> bool:
        """
        Compares the two BIGNUMS or int.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return openssl.bn_cmp(self._backend_bignum, other._backend_bignum) == 0

    @classmethod
    def one(cls):
        return cls(openssl.bn_one())

    def is_zero(self):
        return openssl.bn_is_zero(self._backend_bignum)

    def __mul__(self, other: Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_mul between two BIGNUMS.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return CurveScalar(openssl.bn_mul(self._backend_bignum,
                                          other._backend_bignum,
                                          CURVE.bn_order))

    def __add__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_add on two BIGNUMs.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return CurveScalar(openssl.bn_add(self._backend_bignum,
                                          other._backend_bignum,
                                          CURVE.bn_order))

    def __sub__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_sub on two BIGNUMS.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return CurveScalar(openssl.bn_sub(self._backend_bignum,
                                          other._backend_bignum,
                                          CURVE.bn_order))

    def invert(self) -> 'CurveScalar':
        """
        Performs a BN_mod_inverse.
        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
        """
        return CurveScalar(openssl.bn_invert(self._backend_bignum, CURVE.bn_order))
