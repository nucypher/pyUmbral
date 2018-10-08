"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

from typing import Optional, Tuple

from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes

from umbral import openssl
from umbral.config import default_curve, default_params
from umbral.curve import Curve
from umbral.curvebn import CurveBN
from umbral.params import UmbralParameters


class Point(object):
    """
    Represents an OpenSSL EC_POINT except more Pythonic
    """

    def __init__(self, ec_point, curve: Curve) -> None:
        self.ec_point = ec_point
        self.curve = curve

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None,
                              is_compressed: bool = True):
        """
        Returns the size (in bytes) of a Point given a curve.
        If no curve is provided, it uses the default curve.
        By default, it assumes compressed representation (is_compressed = True).
        """
        curve = curve if curve is not None else default_curve()

        coord_size = curve.field_order_size_in_bytes

        if is_compressed:
            return 1 + coord_size
        else:
            return 1 + 2 * coord_size

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
            affine_x = openssl._int_to_bn(affine_x, curve=None)

        if type(affine_y) == int:
            affine_y = openssl._int_to_bn(affine_y, curve=None)

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

        point = openssl._get_new_EC_POINT(curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_oct2point(
                curve.ec_group, point, data, len(data), bn_ctx);
            backend.openssl_assert(res == 1)

        return cls(point, curve)

    def to_bytes(self, is_compressed: bool=True) -> bytes:
        """
        Returns the Point serialized as bytes. It will return a compressed form
        if is_compressed is set to True.
        """
        length = self.expected_bytes_length(self.curve, is_compressed)

        if is_compressed:
            point_conversion_form = backend._lib.POINT_CONVERSION_COMPRESSED
        else:
            point_conversion_form = backend._lib.POINT_CONVERSION_UNCOMPRESSED

        bin_ptr = backend._ffi.new("unsigned char[]", length)
        with backend._tmp_bn_ctx() as bn_ctx:
            bin_len = backend._lib.EC_POINT_point2oct(
                self.curve.ec_group, self.ec_point, point_conversion_form, 
                bin_ptr, length, bn_ctx
            )
            backend.openssl_assert(bin_len != 0)

        return bytes(backend._ffi.buffer(bin_ptr, bin_len)[:])

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

    def __mul__(self, other: CurveBN) -> 'Point':
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
        return (self + (-other))

    def __neg__(self) -> 'Point':
        """
        Computes the additive inverse of a Point, by performing an 
        EC_POINT_invert on itself.
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


def unsafe_hash_to_point(data : bytes = b'', 
                         params: UmbralParameters = None, 
                         label : bytes = b'') -> 'Point':
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.
    It admits an optional label as an additional input to the hash function.
    It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.

    WARNING: Do not use when the input data is secret, as this implementation is not
    in constant time, and hence, it is not safe with respect to timing attacks.
    """

    params = params if params is not None else default_params()

    len_data = len(data).to_bytes(4, byteorder='big')
    len_label = len(label).to_bytes(4, byteorder='big')

    label_data = len_label + label + len_data + data

    # We use an internal 32-bit counter as additional input
    i = 0
    while i < 2**32:
        ibytes = i.to_bytes(4, byteorder='big')
        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        blake2b.update(label_data + ibytes)
        hash_digest = blake2b.finalize()[:1 + params.CURVE_KEY_SIZE_BYTES]

        sign = b'\x02' if hash_digest[0] & 1 == 0 else b'\x03' 
        compressed_point = sign + hash_digest[1:]

        try:
            return Point.from_bytes(compressed_point, params.curve)
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
