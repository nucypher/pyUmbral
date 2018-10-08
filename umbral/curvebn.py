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

from typing import Optional, Union, cast

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes

from umbral import openssl
from umbral.config import default_curve
from umbral.curve import Curve
from umbral.params import UmbralParameters


class CurveBN(object):
    """
    Represents an OpenSSL Bignum modulo the order of a curve. Some of these
    operations will only work with prime numbers
    By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
    constant time operations.
    """

    def __init__(self, bignum, curve: Curve) -> None:
        on_curve = openssl._bn_is_on_curve(bignum, curve)
        if not on_curve:
            raise ValueError("The provided BIGNUM is not on the provided curve.")

        self.bignum = bignum
        self.curve = curve

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        Returns the size (in bytes) of a CurveBN given the curve,
        which comes from the size of the order of the generated group.
        If no curve is provided, it uses the default.
        """
        curve = curve if curve is not None else default_curve()
        return curve.group_order_size_in_bytes

    @classmethod
    def gen_rand(cls, curve: Optional[Curve] = None) -> 'CurveBN':
        """
        Returns a CurveBN object with a cryptographically secure OpenSSL BIGNUM
        based on the given curve.
        By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
        constant time operations.
        """
        curve = curve if curve is not None else default_curve()

        new_rand_bn = openssl._get_new_BN()
        rand_res = backend._lib.BN_rand_range(new_rand_bn, curve.order)
        backend.openssl_assert(rand_res == 1)

        if not openssl._bn_is_on_curve(new_rand_bn, curve):
            new_rand_bn = cls.gen_rand(curve=curve)
            return new_rand_bn

        return cls(new_rand_bn, curve)

    @classmethod
    def from_int(cls, num: int, curve: Optional[Curve] = None) -> 'CurveBN':
        """
        Returns a CurveBN object from a given integer on a curve.
        By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
        constant time operations.
        """
        curve = curve if curve is not None else default_curve()
        conv_bn = openssl._int_to_bn(num, curve)
        return cls(conv_bn, curve)

    @classmethod
    def hash(cls, *crypto_items, params: UmbralParameters) -> 'CurveBN':
        # TODO: Clean this in an upcoming cleanup of pyUmbral
        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        for item in crypto_items:
            try:
                item_bytes = item.to_bytes()
            except AttributeError:
                if isinstance(item, bytes):
                    item_bytes = item
                else:
                    raise TypeError("{} is not acceptable type, received {}".format(item, type(item)))
            blake2b.update(item_bytes)

        hash_digest = openssl._bytes_to_bn(blake2b.finalize())

        _1 = backend._lib.BN_value_one()
        
        order_minus_1 = openssl._get_new_BN()
        res = backend._lib.BN_sub(order_minus_1, params.curve.order, _1)
        backend.openssl_assert(res == 1)

        bignum = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod(bignum, hash_digest, order_minus_1, bn_ctx)
            backend.openssl_assert(res == 1)

        res = backend._lib.BN_add(bignum, bignum, _1)
        backend.openssl_assert(res == 1)
        
        return cls(bignum, params.curve)

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'CurveBN':
        """
        Returns a CurveBN object from the given byte data that's within the size
        of the provided curve's order.
        By default, the underlying OpenSSL BIGNUM has BN_FLG_CONSTTIME set for
        constant time operations.
        """
        curve = curve if curve is not None else default_curve()

        size = backend._lib.BN_num_bytes(curve.order)
        if len(data) != size:
            raise ValueError("Expected {} B for CurveBNs".format(size))
        bignum = openssl._bytes_to_bn(data)
        return cls(bignum, curve)

    def to_bytes(self) -> bytes:
        """
        Returns the CurveBN as bytes.
        """
        size = backend._lib.BN_num_bytes(self.curve.order)
        return openssl._bn_to_bytes(self.bignum, size)

    def __int__(self) -> int:
        """
        Converts the CurveBN to a Python int.
        """
        return backend._bn_to_int(self.bignum)

    def __eq__(self, other) -> bool:
        """
        Compares the two BIGNUMS or int.
        """
        # TODO: Should this stay in or not?
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = CurveBN(other, self.curve)

        # -1 less than, 0 is equal to, 1 is greater than
        return not bool(backend._lib.BN_cmp(self.bignum, other.bignum))

    def __pow__(self, other: Union[int, 'CurveBN']) -> 'CurveBN':
        """
        Performs a BN_mod_exp on two BIGNUMS.

        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
        """
        # TODO: Should this stay in or not?
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = CurveBN(other, self.curve)

        other = cast('CurveBN', other)  # This is just for mypy

        power = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx, openssl._tmp_bn_mont_ctx(self.curve.order) as bn_mont_ctx:
            res = backend._lib.BN_mod_exp_mont(
                power, self.bignum, other.bignum, self.curve.order, bn_ctx, bn_mont_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(power, self.curve)

    def __mul__(self, other) -> 'CurveBN':
        """
        Performs a BN_mod_mul between two BIGNUMS.
        """
        if type(other) != CurveBN:
            return NotImplemented

        product = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_mul(
                product, self.bignum, other.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(product, self.curve)

    def __truediv__(self, other: 'CurveBN') -> 'CurveBN':
        """
        Performs a BN_div on two BIGNUMs (modulo the order of the curve).

        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.
        """
        product = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            inv_other = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, other.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(inv_other != backend._ffi.NULL)
            inv_other = backend._ffi.gc(inv_other, backend._lib.BN_clear_free)

            res = backend._lib.BN_mod_mul(
                product, self.bignum, inv_other, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(product, self.curve)

    def __add__(self, other : Union[int, 'CurveBN']) -> 'CurveBN':
        """
        Performs a BN_mod_add on two BIGNUMs.
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = CurveBN(other, self.curve)

        other = cast('CurveBN', other)  # This is just for mypy
            
        op_sum = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_add(
                op_sum, self.bignum, other.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(op_sum, self.curve)

    def __sub__(self, other : Union[int, 'CurveBN']) -> 'CurveBN':
        """
        Performs a BN_mod_sub on two BIGNUMS.
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = CurveBN(other, self.curve)

        other = cast('CurveBN', other)  # This is just for mypy

        diff = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_sub(
                diff, self.bignum, other.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(diff, self.curve)

    def __invert__(self) -> 'CurveBN':
        """
        Performs a BN_mod_inverse.

        WARNING: Only in constant time if BN_FLG_CONSTTIME is set on the BN.

        """
        with backend._tmp_bn_ctx() as bn_ctx:
            inv = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, self.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(inv != backend._ffi.NULL)
            inv = backend._ffi.gc(inv, backend._lib.BN_clear_free)

        return CurveBN(inv, self.curve)

    def __neg__(self) -> 'CurveBN':
        """
        Computes the modular opposite (i.e., additive inverse) of a BIGNUM

        """
        zero = backend._int_to_bn(0)
        zero = backend._ffi.gc(zero, backend._lib.BN_clear_free)

        the_opposite = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_sub(
                the_opposite, zero, self.bignum, self.curve.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(the_opposite, self.curve)

    def __mod__(self, other: Union[int, 'CurveBN']) -> 'CurveBN':
        """
        Performs a BN_nnmod on two BIGNUMS.
        """
        if type(other) == int:
            other = openssl._int_to_bn(other)
            other = CurveBN(other, self.curve)

        other = cast('CurveBN', other)  # This is just for mypy

        rem = openssl._get_new_BN()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_nnmod(
                rem, self.bignum, other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return CurveBN(rem, self.curve)
