from typing import TYPE_CHECKING, Optional, Union, Tuple

from . import openssl
from .curve import CURVE
from .serializable import Serializable
if TYPE_CHECKING: # pragma: no cover
    from .hashing import Hash


class CurveScalar(Serializable):
    """
    Represents an OpenSSL Bignum modulo the order of a curve. Some of these
    operations will only work with prime numbers.

    By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
    constant time operations.
    """

    def __init__(self, backend_bignum):
        if not openssl.bn_is_normalized(backend_bignum, CURVE.bn_order):
            raise ValueError("The provided BIGNUM is not on the provided curve.")

        self._backend_bignum = backend_bignum

    @classmethod
    def random_nonzero(cls) -> 'CurveScalar':
        """
        Returns a CurveScalar object with a cryptographically secure OpenSSL BIGNUM.
        """
        return cls(openssl.bn_random_nonzero(CURVE.bn_order))

    @classmethod
    def from_int(cls, num: int) -> 'CurveScalar':
        """
        Returns a CurveScalar object from a given integer on a curve.
        """
        conv_bn = openssl.bn_from_int(num, modulus=CURVE.bn_order)
        return cls(conv_bn)

    @classmethod
    def from_digest(cls, digest: 'Hash') -> 'CurveScalar':
        # TODO (#39): to be replaced by the standard algroithm.
        # Currently just matching what we have in RustCrypto stack
        # (taking bytes modulo curve order).
        # Can produce zeros!
        bn = openssl.bn_from_bytes(digest.finalize(), modulus=CURVE.bn_order)
        return cls(bn)

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['CurveScalar', bytes]:
        scalar_data, data = cls.__take_bytes__(data, CURVE.scalar_size)
        bignum = openssl.bn_from_bytes(scalar_data)
        return cls(bignum), data

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
        if type(other) == int:
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
        return CurveScalar(openssl.bn_mul(self._backend_bignum, other._backend_bignum, CURVE.bn_order))

    def __add__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_add on two BIGNUMs.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return CurveScalar(openssl.bn_add(self._backend_bignum, other._backend_bignum, CURVE.bn_order))

    def __sub__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_sub on two BIGNUMS.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)
        return CurveScalar(openssl.bn_sub(self._backend_bignum, other._backend_bignum, CURVE.bn_order))

    def invert(self) -> 'CurveScalar':
        """
        Performs a BN_mod_inverse.
        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
        """
        return CurveScalar(openssl.bn_invert(self._backend_bignum, CURVE.bn_order))
