from typing import Tuple

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .serializable import Serializable, Deserializable


class CurvePoint(Serializable, Deserializable):
    """
    Represents an OpenSSL EC_POINT except more Pythonic.
    """

    def __init__(self, backend_point) -> None:
        self._backend_point = backend_point

    @classmethod
    def generator(cls) -> 'CurvePoint':
        return cls(CURVE.point_generator)

    @classmethod
    def random(cls) -> 'CurvePoint':
        """
        Returns a CurvePoint object with a cryptographically secure EC_POINT based
        on the provided curve.
        """
        return cls.generator() * CurveScalar.random_nonzero()

    def to_affine(self) -> Tuple[int, int]:
        """
        Returns a tuple of Python ints in the format of (x, y) that represents
        the point in the curve.
        """
        return openssl.point_to_affine_coords(CURVE, self._backend_point)

    @classmethod
    def serialized_size(cls):
        return CURVE.field_element_size + 1 # compressed point size

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        """
        Returns a CurvePoint object from the given byte data on the curve provided.
        """
        return cls(openssl.point_from_bytes(CURVE, data))

    def __bytes__(self) -> bytes:
        """
        Returns the CurvePoint serialized as bytes in the compressed form.
        """
        return openssl.point_to_bytes_compressed(CURVE, self._backend_point)

    def __eq__(self, other):
        """
        Compares two EC_POINTS for equality.
        """
        return openssl.point_eq(CURVE, self._backend_point, other._backend_point)

    def __mul__(self, other: CurveScalar) -> 'CurvePoint':
        """
        Performs an EC_POINT_mul on an EC_POINT and a BIGNUM.
        """
        return CurvePoint(openssl.point_mul_bn(CURVE, self._backend_point, other._backend_bignum))

    def __add__(self, other: 'CurvePoint') -> 'CurvePoint':
        """
        Performs an EC_POINT_add on two EC_POINTS.
        """
        return CurvePoint(openssl.point_add(CURVE, self._backend_point, other._backend_point))

    def __sub__(self, other: 'CurvePoint') -> 'CurvePoint':
        """
        Performs subtraction by adding the inverse of the `other` to the point.
        """
        return self + (-other)

    def __neg__(self) -> 'CurvePoint':
        """
        Computes the additive inverse of a CurvePoint, by performing an
        EC_POINT_invert on itself.
        """
        return CurvePoint(openssl.point_neg(CURVE, self._backend_point))
