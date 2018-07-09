from typing import Optional, Tuple

from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes

from umbral import openssl
from umbral.config import default_curve
from umbral.curve import Curve
from umbral.curvebn import CurveBN
from umbral.params import UmbralParameters
from umbral.utils import get_field_order_size_in_bytes


class Point(object):
    """
    Represents an OpenSSL EC_POINT except more Pythonic
    """

    def __init__(self, ec_point, curve: Curve) -> None:
        self.ec_point = ec_point
        self.curve = curve

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        Returns the size (in bytes) of a compressed Point given a curve.
        If no curve is provided, it uses the default curve.
        """
        curve = curve if curve is not None else default_curve()
        return get_field_order_size_in_bytes(curve) + 1

    @classmethod
    def gen_rand(cls, curve: Optional[Curve] = None) -> 'Point':
        """
        Returns a Point object with a cryptographically secure EC_POINT based
        on the provided curve.
        """
        curve = curve if curve is not None else default_curve()

        rand_point = openssl._get_new_EC_POINT(curve)
        rand_bn = CurveBN.gen_rand(curve).bignum

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                curve.ec_group, rand_point, backend._ffi.NULL, curve.generator,
                rand_bn, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return cls(rand_point, curve)

    @classmethod
    def from_affine(cls, coords: Tuple[int, int], curve: Optional[Curve] = None) -> 'Point':
        """
        Returns a Point object from the given affine coordinates in a tuple in
        the format of (x, y) and a given curve.
        """
        curve = curve if curve is not None else default_curve()

        affine_x, affine_y = coords
        if type(affine_x) == int:
            affine_x = openssl._int_to_bn(affine_x, curve=curve)

        if type(affine_y) == int:
            affine_y = openssl._int_to_bn(affine_y, curve=curve)

        ec_point = openssl._get_EC_POINT_via_affine(affine_x, affine_y, curve)
        return cls(ec_point, curve)

    def to_affine(self):
        """
        Returns a tuple of Python ints in the format of (x, y) that represents
        the point in the curve.
        """
        affine_x, affine_y = openssl._get_affine_coords_via_EC_POINT(
                                self.ec_point, self.curve)
        return (backend._bn_to_int(affine_x), backend._bn_to_int(affine_y))

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'Point':
        """
        Returns a Point object from the given byte data on the curve provided.
        """
        curve = curve if curve is not None else default_curve()

        compressed_size = cls.expected_bytes_length(curve)
        # Check if compressed
        if data[0] in [2, 3]:
            if len(data) != compressed_size:
                raise ValueError("X coordinate too large for curve.")

            affine_x = CurveBN.from_bytes(data[1:], curve)
            type_y = data[0] - 2

            ec_point = openssl._get_new_EC_POINT(curve)
            with backend._tmp_bn_ctx() as bn_ctx:
                res = backend._lib.EC_POINT_set_compressed_coordinates_GFp(
                    curve.ec_group, ec_point, affine_x.bignum, type_y, bn_ctx
                )
                backend.openssl_assert(res == 1)
            return cls(ec_point, curve)

        # Handle uncompressed point
        # TODO: Give better error messages
        elif data[0] == 4:
            coord_size = compressed_size - 1
            uncompressed_size = 1 + (2 * coord_size)
            if len(data) != uncompressed_size:
                raise ValueError("Uncompressed point does not have right size.")
            affine_x = int.from_bytes(data[1:coord_size+1], 'big')
            affine_y = int.from_bytes(data[1+coord_size:], 'big')

            return cls.from_affine((affine_x, affine_y), curve)
        else:
            raise ValueError("Invalid point serialization.")

    def to_bytes(self, is_compressed: bool=True) -> bytes:
        """
        Returns the Point serialized as bytes. It will return a compressed form
        if is_compressed is set to True.
        """
        affine_x, affine_y = self.to_affine()
        key_size = get_field_order_size_in_bytes(self.curve)

        if is_compressed:
            y_bit = (affine_y & 1) + 2
            data = int.to_bytes(y_bit, 1, 'big')
            data += int.to_bytes(affine_x, key_size, 'big')
        else:
            data = b'\x04'
            data += int.to_bytes(affine_x, key_size, 'big')
            data += int.to_bytes(affine_y, key_size, 'big')

        return data

    @classmethod
    def get_generator_from_curve(cls, curve: Optional[Curve] = None) -> 'Point':
        """
        Returns the generator Point from the given curve as a Point object.
        """
        curve = curve if curve is not None else default_curve()
        return cls(curve.generator, curve)

    def __eq__(self, other):
        """
        Compares two EC_POINTS for equality.
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            is_equal = backend._lib.EC_POINT_cmp(
                self.curve.ec_group, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(is_equal != -1)

        # 1 is not-equal, 0 is equal, -1 is error
        return not bool(is_equal)

    def __mul__(self, other) -> 'Point':
        """
        Performs an EC_POINT_mul on an EC_POINT and a BIGNUM.
        """
        # TODO: Check that both points use the same curve.
        prod = openssl._get_new_EC_POINT(self.curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                self.curve.ec_group, prod, backend._ffi.NULL,
                self.ec_point, other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(prod, self.curve)

    __rmul__ = __mul__

    def __add__(self, other) -> 'Point':
        """
        Performs an EC_POINT_add on two EC_POINTS.
        """
        op_sum = openssl._get_new_EC_POINT(self.curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_add(
                self.curve.ec_group, op_sum, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return Point(op_sum, self.curve)

    def __sub__(self, other):
        """
        Performs subtraction by adding the inverse of the `other` to the point.
        """
        return (self + (~other))

    def __invert__(self) -> 'Point':
        """
        Performs an EC_POINT_invert on itself.
        """
        inv = backend._lib.EC_POINT_dup(self.ec_point, self.curve.ec_group)
        backend.openssl_assert(inv != backend._ffi.NULL)
        inv = backend._ffi.gc(inv, backend._lib.EC_POINT_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_invert(
                self.curve.ec_group, inv, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return Point(inv, self.curve)

    def __bytes__(self) -> bytes:
        return self.to_bytes()


def unsafe_hash_to_point(data, params: UmbralParameters, label=None) -> 'Point':
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.
    It admits an optional label as an additional input to the hash function.
    It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.

    WARNING: Do not use when the input data is secret, as this implementation is not
    in constant time, and hence, it is not safe with respect to timing attacks.

    TODO: Check how to uniformly generate ycoords. Currently, it only outputs points
    where ycoord is even (i.e., starting with 0x02 in compressed notation)
    """
    if label is None:
        label = []

    # We use a 32-bit counter as additional input
    i = 1
    while i < 2**32:
        ibytes = i.to_bytes(4, byteorder='big')
        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        blake2b.update(label + ibytes + data)
        hash_digest = blake2b.finalize()[:params.CURVE_KEY_SIZE_BYTES]

        compressed02 = b"\x02" + hash_digest

        try:
            return Point.from_bytes(compressed02, params.curve)
        except InternalError as e:
            # We want to catch specific InternalExceptions:
            # - Point not in the curve (code 107)
            # - Invalid compressed point (code 110)
            # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
            if e.err_code[0].reason in (107, 110):
                pass
            else:
                # Any other exception, we raise it
                raise e

        i += 1

    # Only happens with probability 2^(-32)
    raise ValueError('Could not hash input into the curve')
