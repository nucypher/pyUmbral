from umbral.bignum import BigNum
from cryptography.hazmat.backends.openssl import backend


class Point(object):
    """
    Represents an OpenSSL EC_POINT except more Pythonic
    """

    def __init__(self, ec_point, curve_nid, group, generator):
        self.ec_point = ec_point
        self.curve_nid = curve_nid
        self.group = group
        self.generator = generator

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

            on_curve = backend._lib.EC_POINT_is_on_curve(
                group, rand_point, bn_ctx
            )
            if on_curve != 1:
                raise ValueError("Generated point is not on curve.")

        return Point(rand_point, curve_nid, group, generator)
