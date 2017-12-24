import os
from cryptography.hazmat.backends.openssl import backend


class BigNum(object):
    """
    Represents an OpenSSL BIGNUM except more Pythonic
    """

    def __init__(self, bignum, curve_nid, curve_group, curve_order):
        self.bignum = bignum
        self.curve_nid = curve_nid
        self.curve_group = curve_group
        self.curve_order = curve_order

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
        rand_num = int.from_bytes(os.urandom(curve.key_size // 8), 'big')
        while rand_num >= order_int or rand_num <= 0:
            rand_num = int.from_bytes(os.urandom(curve.key_size // 8), 'big')

        new_rand_bn = backend._int_to_bn(rand_num)
        new_rand_bn = backend._ffi.gc(new_rand_bn, backend._lib.BN_free)

        return BigNum(new_rand_bn, curve_nid, group, order)

    def __int__(self):
        return backend._bn_to_int(self.bignum)
