from umbral.bignum import BigNum
from cryptography.hazmat.backends.openssl import backend


class Point(object):
    """
    Represents an OpenSSL EC_POINT except more Pythonic
    """

    def __init__(self, ec_point, curve_nid, group):
        self.ec_point = ec_point
        self.curve_nid = curve_nid
        self.group = group

    @classmethod
    def gen_rand(cls, curve):
        """
        Returns a Point object with a cryptographically secure EC_POINT based
        on the provided curve.
        """
        curve_nid = backend._elliptic_curve_to_nid(curve)

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        generator = backend._lib.EC_GROUP_get0_generator(group)
        backend.openssl_assert(generator != backend._ffi.NULL)

        rand_point = backend._lib.EC_POINT_new(group)
        backend.openssl_assert(rand_point != backend._ffi.NULL)
        rand_point = backend._ffi.gc(rand_point, backend._lib.EC_POINT_free)

        rand_bn = BigNum.gen_rand(curve).bignum

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                group, rand_point, backend._ffi.NULL, generator, rand_bn, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(rand_point, curve_nid, group)

    @classmethod
    def from_affine(cls, coords, curve):
        """
        Returns a Point object from the given affine coordinates in a tuple in
        the format of (x, y) and a given curve.
        """
        try:
            curve_nid = backend._elliptic_curve_to_nid(curve)
        except AttributeError:
            # Presume that the user passed in the curve_nid
            curve_nid = curve

        affine_x, affine_y = coords
        if type(affine_x) == int:
            affine_x = backend._int_to_bn(affine_x)
            affine_x = backend._ffi.gc(affine_x, backend._lib.BN_free)

        if type(affine_y) == int:
            affine_y = backend._int_to_bn(affine_y)
            affine_y = backend._ffi.gc(affine_y, backend._lib.BN_free)

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        ec_point = backend._lib.EC_POINT_new(group)
        backend.openssl_assert(ec_point != backend._ffi.NULL)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_set_affine_coordinates_GFp(
                group, ec_point, affine_x, affine_y, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(ec_point, curve_nid, group)

    def __mul__(self, other):
        """
        Performs an EC_POINT_mul on an EC_POINT and a BIGNUM.
        """
        prod = backend._lib.EC_POINT_new(self.group)
        backend.openssl_assert(prod != backend._ffi.NULL)
        prod = backend._ffi.gc(prod, backend._lib.EC_POINT_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_mul(
                self.group, prod, backend._ffi.NULL, self.ec_point,
                other.bignum, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(prod, self.curve_nid, self.group)

    def __add__(self, other):
        """
        Performs an EC_POINT_add on two EC_POINTS.
        """
        sum = backend._lib.EC_POINT_new(self.group)
        backend.openssl_assert(sum != backend._ffi.NULL)
        sum = backend._ffi.gc(sum, backend._lib.EC_POINT_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_add(
                self.group, sum, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(sum, self.curve_nid, self.group)

    def __sub__(self, other):
        """
        Performs subtraction by adding the inverse of the `other` to the point.
        """
        return (self + (~other))

    def __invert__(self):
        """
        Performs an EC_POINT_invert on itself.
        """
        inv = backend._lib.EC_POINT_dup(self.ec_point, self.group)
        backend.openssl_assert(inv != backend._ffi.NULL)
        inv = backend._ffi.gc(inv, backend._lib.EC_POINT_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_invert(
                self.group, inv, bn_ctx
            )
            backend.openssl_assert(res == 1)

        return Point(inv, self.curve_nid, self.group)
