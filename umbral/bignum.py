import os
from cryptography.hazmat.backends.openssl import backend


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
    def gen_rand(cls, curve):
        """
        Returns a BigNum object with a cryptographically secure BigNum based
        on the given curve.
        """
        curve_nid = backend._elliptic_curve_to_nid(curve)



        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        order = backend._lib.BN_new()
        backend.openssl_assert(order != backend._ffi.NULL)
        order = backend._ffi.gc(order, backend._lib.BN_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
            backend.openssl_assert(res == 1)

        order_int = backend._bn_to_int(order)

        # Generate random number on curve
        # TODO: Can we utilize a better way to do this via OpenSSL or crypto.io?
        rand_num = int.from_bytes(os.urandom(curve.key_size // 8), 'big')
        while rand_num >= order_int or rand_num <= 0:
            rand_num = int.from_bytes(os.urandom(curve.key_size // 8), 'big')

        new_rand_bn = backend._int_to_bn(rand_num)
        new_rand_bn = backend._ffi.gc(new_rand_bn, backend._lib.BN_free)

        return BigNum(new_rand_bn, curve_nid, group, order)

    @classmethod
    def from_int(cls, num, curve):
        """
        Returns a BigNum object from a given integer on a curve.
        """
        try:
            curve_nid = backend._elliptic_curve_to_nid(curve)
        except AttributeError:
            # Presume that the user passed in the curve_nid
            curve_nid = curve

        

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        order = backend._lib.BN_new()
        backend.openssl_assert(order != backend._ffi.NULL)
        order = backend._ffi.gc(order, backend._lib.BN_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
            backend.openssl_assert(res == 1)

        order_int = backend._bn_to_int(order)
        if num <= 0 or num >= order_int:
            # TODO: Handle this better maybe? Ask David.
            raise ValueError("Integer provided is not on the given curve.")

        bignum = backend._int_to_bn(num)
        bignum = backend._ffi.gc(bignum, backend._lib.BN_free)

        return BigNum(bignum, curve_nid, group, order)

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
            other = backend._ffi.gc(other, backend._lib.BN_free)

            other = BigNum(other, None, None, None)

        # -1 less than, 0 is equal to, 1 is greater than
        return not bool(backend._lib.BN_cmp(self.bignum, other.bignum))

    def __pow__(self, other):
        """
        Performs a BN_mod_exp on two BIGNUMS.
        """
        if type(other) == int:
            other = backend._int_to_bn(other)
            other = backend._ffi.gc(other, backend._lib.BN_free)

            other = BigNum(other, None, None, None)

        power = backend._lib.BN_new()
        backend.openssl_assert(power != backend._ffi.NULL)
        power = backend._ffi.gc(power, backend._lib.BN_free)

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
        product = backend._lib.BN_new()
        backend.openssl_assert(product != backend._ffi.NULL)
        product = backend._ffi.gc(product, backend._lib.BN_free)

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
        product = backend._ffi.gc(product, backend._lib.BN_free)

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
        sum = backend._ffi.gc(sum, backend._lib.BN_free)

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
        diff = backend._ffi.gc(diff, backend._lib.BN_free)

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
            inv = backend._ffi.gc(inv, backend._lib.BN_free)

        return BigNum(inv, self.curve_nid, self.group, self.order)

    def __mod__(self, other):
        """
        Performs a BN_nnmod on two BIGNUMS.
        """
        if type(other) == int:
            other = backend._int_to_bn(other)
            other = backend._ffi.gc(other, backend._lib.BN_free)

            other = BigNum(other, None, None, None)

        rem = backend._lib.BN_new()
        backend.openssl_assert(rem != backend._ffi.NULL)
        rem = backend._ffi.gc(rem, backend._lib.BN_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_nnmod(
                rem, self.bignum, other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return BigNum(rem, self.curve_nid, self.group, self.order)
