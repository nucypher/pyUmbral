from typing import Optional, Tuple

from cryptography.hazmat.backends.openssl import backend

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .serializable import Serializable


class CurvePoint(Serializable):
    """
    Represents an OpenSSL EC_POINT except more Pythonic.
    """

    def __init__(self, backend_point) -> None:
        self._backend_point = backend_point

    @classmethod
    def generator(cls) -> 'CurvePoint':
        return cls(CURVE.generator)

    @classmethod
    def random(cls) -> 'CurvePoint':
        """
        Returns a CurvePoint object with a cryptographically secure EC_POINT based
        on the provided curve.
        """
        return cls.generator() * CurveScalar.random_nonzero()

    @classmethod
    def from_affine(cls, coords: Tuple[int, int]) -> 'CurvePoint':
        """
        Returns a CurvePoint object from the given affine coordinates in a tuple in
        the format of (x, y) and a given curve.
        """
        affine_x, affine_y = coords
        if type(affine_x) == int:
            affine_x = openssl._int_to_bn(affine_x, curve=None)

        if type(affine_y) == int:
            affine_y = openssl._int_to_bn(affine_y, curve=None)

        backend_point = openssl._get_EC_POINT_via_affine(affine_x, affine_y, CURVE)
        return cls(backend_point)

    def to_affine(self):
        """
        Returns a tuple of Python ints in the format of (x, y) that represents
        the point in the curve.
        """
        affine_x, affine_y = openssl._get_affine_coords_via_EC_POINT(self._backend_point, CURVE)
        return (backend._bn_to_int(affine_x), backend._bn_to_int(affine_y))

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['CurvePoint', bytes]:
        """
        Returns a CurvePoint object from the given byte data on the curve provided.
        """
        size = CURVE.field_order_size_in_bytes + 1 # compressed point size
        point_data, data = cls.__take_bytes__(data, size)

        point = openssl._get_new_EC_POINT(CURVE)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_oct2point(
                CURVE.ec_group, point, point_data, len(point_data), bn_ctx);
            backend.openssl_assert(res == 1)

        return cls(point), data

    def __bytes__(self) -> bytes:
        """
        Returns the CurvePoint serialized as bytes in the compressed form.
        """
        point_conversion_form = backend._lib.POINT_CONVERSION_COMPRESSED
        size = CURVE.field_order_size_in_bytes + 1 # compressed point size

        bin_ptr = backend._ffi.new("unsigned char[]", size)
        with backend._tmp_bn_ctx() as bn_ctx:
            bin_len = backend._lib.EC_POINT_point2oct(
                CURVE.ec_group, self._backend_point, point_conversion_form,
                bin_ptr, size, bn_ctx
            )
            backend.openssl_assert(bin_len != 0)

        return bytes(backend._ffi.buffer(bin_ptr, bin_len)[:])

    def __eq__(self, other):
        """
        Compares two EC_POINTS for equality.
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            is_equal = backend._lib.EC_POINT_cmp(
                CURVE.ec_group, self._backend_point, other._backend_point, bn_ctx
            )
            backend.openssl_assert(is_equal != -1)

        # 1 is not-equal, 0 is equal, -1 is error
        return not bool(is_equal)

    def __mul__(self, other: CurveScalar) -> 'CurvePoint':
        """
        Performs an EC_POINT_mul on an EC_POINT and a BIGNUM.
        """
        # TODO: Check that both points use the same curve.
        prod = openssl._get_new_EC_POINT(CURVE)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                CURVE.ec_group, prod, backend._ffi.NULL,
                self._backend_point, other._backend_bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurvePoint(prod)

    def __add__(self, other: 'CurvePoint') -> 'CurvePoint':
        """
        Performs an EC_POINT_add on two EC_POINTS.
        """
        op_sum = openssl._get_new_EC_POINT(CURVE)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_add(
                CURVE.ec_group, op_sum, self._backend_point, other._backend_point, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return CurvePoint(op_sum)

    def __sub__(self, other: 'CurvePoint') -> 'CurvePoint':
        """
        Performs subtraction by adding the inverse of the `other` to the point.
        """
        return (self + (-other))

    def __neg__(self) -> 'CurvePoint':
        """
        Computes the additive inverse of a CurvePoint, by performing an
        EC_POINT_invert on itself.
        """
        inv = backend._lib.EC_POINT_dup(self._backend_point, CURVE.ec_group)
        backend.openssl_assert(inv != backend._ffi.NULL)
        inv = backend._ffi.gc(inv, backend._lib.EC_POINT_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_invert(
                CURVE.ec_group, inv, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return CurvePoint(inv)
