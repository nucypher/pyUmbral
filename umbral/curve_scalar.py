from typing import Optional, Union, Tuple

from cryptography.hazmat.backends.openssl import backend

from . import openssl
from .curve import CURVE
from .serializable import Serializable


class CurveScalar(Serializable):
    """
    Represents an OpenSSL Bignum modulo the order of a curve. Some of these
    operations will only work with prime numbers.
    By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
    constant time operations.
    """

    def __init__(self, backend_bignum):
        on_curve = openssl._bn_is_on_curve(backend_bignum, CURVE)
        if not on_curve:
            raise ValueError("The provided BIGNUM is not on the provided curve.")

        self._backend_bignum = backend_bignum

    @classmethod
    def random_nonzero(cls) -> 'CurveScalar':
        """
        Returns a CurveScalar object with a cryptographically secure OpenSSL BIGNUM.
        """
        one = backend._lib.BN_value_one()

        # TODO: in most cases, we want this number to be secret.
        # OpenSSL 1.1.1 has `BN_priv_rand_range()`, but it is not
        # currently exported by `cryptography`.
        # Use when available.

        # Calculate `order - 1`
        order_minus_1 = openssl._get_new_BN()
        res = backend._lib.BN_sub(order_minus_1, CURVE.order, one)
        backend.openssl_assert(res == 1)

        # Get a random in range `[0, order - 1)`
        new_rand_bn = openssl._get_new_BN()
        res = backend._lib.BN_rand_range(new_rand_bn, order_minus_1)
        backend.openssl_assert(res == 1)

        # Turn it into a random in range `[1, order)`
        op_sum = openssl._get_new_BN()
        res = backend._lib.BN_add(op_sum, new_rand_bn, one)
        backend.openssl_assert(res == 1)

        return cls(op_sum)

    @classmethod
    def from_int(cls, num: int) -> 'CurveScalar':
        """
        Returns a CurveScalar object from a given integer on a curve.
        """
        conv_bn = openssl._int_to_bn(num, CURVE)
        return cls(conv_bn)

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['CurveScalar', bytes]:
        size = backend._lib.BN_num_bytes(CURVE.order)
        scalar_data, data = cls.__take_bytes__(data, size)
        bignum = openssl._bytes_to_bn(scalar_data)
        return cls(bignum), data

    def __bytes__(self) -> bytes:
        """
        Returns the CurveScalar as bytes.
        """
        size = backend._lib.BN_num_bytes(CURVE.order)
        return openssl._bn_to_bytes(self._backend_bignum, size)

    def __int__(self) -> int:
        """
        Converts the CurveScalar to a Python int.
        """
        return backend._bn_to_int(self._backend_bignum)

    def __eq__(self, other) -> bool:
        """
        Compares the two BIGNUMS or int.
        """
        if type(other) == int:
            other = CurveScalar.from_int(other)

        # -1 less than, 0 is equal to, 1 is greater than
        return not bool(backend._lib.BN_cmp(self._backend_bignum, other._backend_bignum))

    def is_zero(self):
        # BN_is_zero() is not exported, so this will have to do
        return self == 0

    def __mul__(self, other: Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_mul between two BIGNUMS.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)

        product = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_mul(
                product, self._backend_bignum, other._backend_bignum, CURVE.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveScalar(product)

    def __add__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_add on two BIGNUMs.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)

        op_sum = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_add(
                op_sum, self._backend_bignum, other._backend_bignum, CURVE.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveScalar(op_sum)

    def __sub__(self, other : Union[int, 'CurveScalar']) -> 'CurveScalar':
        """
        Performs a BN_mod_sub on two BIGNUMS.
        """
        if isinstance(other, int):
            other = CurveScalar.from_int(other)

        diff = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_sub(
                diff, self._backend_bignum, other._backend_bignum, CURVE.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveScalar(diff)

    def invert(self) -> 'CurveScalar':
        """
        Performs a BN_mod_inverse.
        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            inv = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, self._backend_bignum, CURVE.order, bn_ctx
            )
            backend.openssl_assert(inv != backend._ffi.NULL)
            inv = backend._ffi.gc(inv, backend._lib.BN_clear_free)

        return CurveScalar(inv)
