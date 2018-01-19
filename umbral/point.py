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

    def to_affine(self):
        """
        Returns a tuple of Python ints in the format of (x, y) that represents
        the point in the curve.
        """
        affine_x = backend._lib.BN_new()
        backend.openssl_assert(affine_x != backend._ffi.NULL)
        affine_x = backend._ffi.gc(affine_x, backend._lib.BN_free)

        affine_y = backend._lib.BN_new()
        backend.openssl_assert(affine_y != backend._ffi.NULL)
        affine_y = backend._ffi.gc(affine_y, backend._lib.BN_free)

        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_get_affine_coordinates_GFp(
                self.group, self.ec_point, affine_x, affine_y, bn_ctx
            )
            backend.openssl_assert(res == 1)
        return (backend._bn_to_int(affine_x), backend._bn_to_int(affine_y))

    @classmethod
    def from_bytes(self, data, curve):
        """
        Returns a Point object from the given byte data on the curve provided.
        """
        try:
            curve_nid = backend._elliptic_curve_to_nid(curve)
        except AttributeError:
            # Presume that the user passed in the curve_nid
            curve_nid = curve

        # Check if compressed
        if data[0] in [2, 3]:
            type_y = data[0] - 2

            if len(data[1:]) > curve.key_size // 8:
                raise ValueError("X coordinate too large for curve.")

            affine_x = BigNum.from_bytes(data[1:], curve)

            ec_point = backend._lib.EC_POINT_new(affine_x.group)
            backend.openssl_assert(ec_point != backend._ffi.NULL)
            ec_point = backend._ffi.gc(ec_point, backend._lib.EC_POINT_free)

            with backend._tmp_bn_ctx() as bn_ctx:
                res = backend._lib.EC_POINT_set_compressed_coordinates_GFp(
                    affine_x.group, ec_point, affine_x.bignum, type_y, bn_ctx
                )
                backend.openssl_assert(res == 1)

            return Point(ec_point, curve_nid, affine_x.group)

        # Handle uncompressed point
        elif data[0] == 4:
            key_size = curve.key_size // 8
            affine_x = int.from_bytes(data[1:key_size+1], 'big')
            affine_y = int.from_bytes(data[1+key_size:], 'big')

            return Point.from_affine((affine_x, affine_y), curve)
        else:
            raise ValueError("Invalid point serialization.")

    def to_bytes(self, is_compressed=True):
        """
        Returns the Point serialized as bytes. It will return a compressed form
        if is_compressed is set to True.
        """
        affine_x, affine_y = self.to_affine()

        # Get size of curve via order
        order = Point.get_order_from_curve(self.curve_nid)
        key_size = backend._lib.BN_num_bytes(order.bignum)

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
    def get_generator_from_curve(cls, curve):
        """
        Returns the generator Point from the given curve as a Point object.
        """
        try:
            curve_nid = backend._elliptic_curve_to_nid(curve)
        except AttributeError:
            # Presume that the user passed in the curve_nid
            curve_nid = curve

        group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
        backend.openssl_assert(group != backend._ffi.NULL)

        generator = backend._lib.EC_GROUP_get0_generator(group)
        backend.openssl_assert(generator != backend._ffi.NULL)

        return Point(generator, curve_nid, group)

    @classmethod
    def get_order_from_curve(cls, curve):
        """
        Returns the order from the given curve as a BigNum.
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

        return BigNum(order, curve_nid, group, order)

    def __eq__(self, other):
        """
        Compares two EC_POINTS for equality.
        """
        with backend._tmp_bn_ctx() as bn_ctx:
            is_equal = backend._lib.EC_POINT_cmp(
                self.group, self.ec_point, other.ec_point, bn_ctx
            )
            backend.openssl_assert(is_equal != -1)

        # 1 is not-equal, 0 is equal, -1 is error
        return not bool(is_equal)

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

    __rmul__ = __mul__

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
