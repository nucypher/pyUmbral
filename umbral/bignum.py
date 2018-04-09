import os

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from umbral.config import default_curve
from umbral.utils import get_curve_keysize_bytes
import umbral.point


class BigNum(object):
    """
    Represents an OpenSSL BIGNUM except more Pythonic
    """

    def __init__(self, bignum, curve_nid, group, order):
        self.bignum = bignum
        self.curve_nid = curve_nid
        self.group = group
        self.order = order

    @classmethod
    def gen_rand(cls, curve: ec.EllipticCurve = None):
        """
        Returns a BigNum object with a cryptographically secure BigNum based
        on the given curve.
        """
        curve = curve if curve is not None else default_curve()
        curve_nid = backend._elliptic_curve_to_nid(curve)

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        order = backend._lib.BN_new()
        backend.openssl_assert(order != backend._ffi.NULL)
        order = backend._ffi.gc(order, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
            backend.openssl_assert(res == 1)

        new_rand_bn = backend._lib.BN_new()
        backend.openssl_assert(new_rand_bn != backend._ffi.NULL)
        new_rand_bn = backend._ffi.gc(new_rand_bn, backend._lib.BN_clear_free)

        rand_res = backend._lib.BN_rand_range(new_rand_bn, order)
        backend.openssl_assert(rand_res == 1)

        return cls(new_rand_bn, curve_nid, group, order)

    @classmethod
    def from_int(cls, num, curve: ec.EllipticCurve=None):
        """
        Returns a BigNum object from a given integer on a curve.
        """
        curve = curve if curve is not None else default_curve()
        try:
            curve_nid = backend._elliptic_curve_to_nid(curve)
        except AttributeError:
            # Presume that the user passed in the curve_nid
            curve_nid = curve

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        order = backend._lib.BN_new()
        backend.openssl_assert(order != backend._ffi.NULL)
        order = backend._ffi.gc(order, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
            backend.openssl_assert(res == 1)

        order_int = backend._bn_to_int(order)
        if num <= 0 or num >= order_int:
            # TODO: Handle this better maybe? Ask David.
            raise ValueError("Integer provided is not on the given curve.")

        bignum = backend._int_to_bn(num)
        bignum = backend._ffi.gc(bignum, backend._lib.BN_clear_free)

        return cls(bignum, curve_nid, group, order)

    @classmethod
    def from_bytes(cls, data, curve: ec.EllipticCurve=None):
        """
        Returns a BigNum object from the given byte data that's within the size
        of the provided curve's order.
        """
        curve = curve if curve is not None else default_curve()
        num = int.from_bytes(data, 'big')

        return BigNum.from_int(num, curve)

    def to_bytes(self):
        """
        Returns the BigNum as bytes.
        """
        size = backend._lib.BN_num_bytes(self.order)

        return int.to_bytes(int(self), size, 'big')

    def __int__(self):
        """
        Converts the BigNum to a Python int.
        """
        return backend._bn_to_int(self.bignum)

    def __eq__(self, other):
        """
        Compares the two BIGNUMS or int.
        """
        if type(other) == int:
            other = backend._int_to_bn(other)
            other = backend._ffi.gc(other, backend._lib.BN_clear_free)

            other = BigNum(other, None, None, None)

        # -1 less than, 0 is equal to, 1 is greater than
        return not bool(backend._lib.BN_cmp(self.bignum, other.bignum))

    def __pow__(self, other):
        """
        Performs a BN_mod_exp on two BIGNUMS.
        """
        if type(other) == int:
            other = backend._int_to_bn(other)
            other = backend._ffi.gc(other, backend._lib.BN_clear_free)

            other = BigNum(other, None, None, None)

        power = backend._lib.BN_new()
        backend.openssl_assert(power != backend._ffi.NULL)
        power = backend._ffi.gc(power, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_exp(
                power, self.bignum, other.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(power, self.curve_nid, self.group, self.order)

    def __mul__(self, other):
        """
        Performs a BN_mod_mul between two BIGNUMS.
        """
        if type(other) != BigNum:
            return NotImplemented

        product = backend._lib.BN_new()
        backend.openssl_assert(product != backend._ffi.NULL)
        product = backend._ffi.gc(product, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_mul(
                product, self.bignum, other.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(product, self.curve_nid, self.group, self.order)

    def __truediv__(self, other):
        """
        Performs a BN_div on two BIGNUMs (modulo the order of the curve).
        """
        product = backend._lib.BN_new()
        backend.openssl_assert(product != backend._ffi.NULL)
        product = backend._ffi.gc(product, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            inv_other = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, other.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(inv_other != backend._ffi.NULL)

            res = backend._lib.BN_mod_mul(
                product, self.bignum, inv_other, self.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(product, self.curve_nid, self.group, self.order)

    def __add__(self, other):
        """
        Performs a BN_mod_add on two BIGNUMs.
        """
        sum = backend._lib.BN_new()
        backend.openssl_assert(sum != backend._ffi.NULL)
        sum = backend._ffi.gc(sum, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_add(
                sum, self.bignum, other.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(sum, self.curve_nid, self.group, self.order)

    def __sub__(self, other):
        """
        Performs a BN_mod_sub on two BIGNUMS.
        """
        diff = backend._lib.BN_new()
        backend.openssl_assert(diff != backend._ffi.NULL)
        diff = backend._ffi.gc(diff, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod_sub(
                diff, self.bignum, other.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(diff, self.curve_nid, self.group, self.order)

    def __invert__(self):
        """
        Performs a BN_mod_inverse.
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            inv = backend._lib.BN_mod_inverse(
                backend._ffi.NULL, self.bignum, self.order, bn_ctx
            )
            backend.openssl_assert(inv != backend._ffi.NULL)
            inv = backend._ffi.gc(inv, backend._lib.BN_clear_free)

        return BigNum(inv, self.curve_nid, self.group, self.order)

    def __mod__(self, other):
        """
        Performs a BN_nnmod on two BIGNUMS.
        """
        if type(other) == int:
            other = backend._int_to_bn(other)
            other = backend._ffi.gc(other, backend._lib.BN_clear_free)

            other = BigNum(other, None, None, None)

        rem = backend._lib.BN_new()
        backend.openssl_assert(rem != backend._ffi.NULL)
        rem = backend._ffi.gc(rem, backend._lib.BN_clear_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_nnmod(
                rem, self.bignum, other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(rem, self.curve_nid, self.group, self.order)

    def __hash__(self):
        return hash(int(self))


def hash_to_bn(crypto_items, params):
    if not isinstance(crypto_items, list):
        crypto_items = [crypto_items]

    valid_instance_types = (BigNum, umbral.point.Point)

    blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
    for item in crypto_items:
        if isinstance(item, valid_instance_types):
            data_bytes = item.to_bytes()
        else:
            data_bytes = item
        blake2b.update(data_bytes)

    i = 0
    h = 0
    while h < params.CURVE_MINVAL_HASH_512:
        blake2b_i = blake2b.copy()
        blake2b_i.update(i.to_bytes(params.CURVE_KEY_SIZE_BYTES, 'big'))
        hash_digest = blake2b_i.finalize()
        h = int.from_bytes(hash_digest, byteorder='big', signed=False)
        i += 1
    hash_bn = h % int(params.order)

    res = BigNum.from_int(hash_bn, params.curve)

    return res
