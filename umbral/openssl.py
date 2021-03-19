from contextlib import contextmanager
from typing import Tuple

from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey, _EllipticCurvePublicKey


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    curve_nid, the EC_GROUP struct, and the order of the curve.

    Contains a whitelist of supported elliptic curves used in pyUmbral.
    """

    _supported_curves = {
        415: 'secp256r1',
        714: 'secp256k1',
        715: 'secp384r1'
    }

    @staticmethod
    def _get_ec_group_by_curve_nid(nid: int):
        """
        Returns the group of a given curve via its OpenSSL nid. This must be freed
        after each use otherwise it leaks memory.
        """
        group = backend._lib.EC_GROUP_new_by_curve_name(nid)
        backend.openssl_assert(group != backend._ffi.NULL)
        return group

    @staticmethod
    def _get_ec_order_by_group(ec_group):
        """
        Returns the order of a given curve via its OpenSSL EC_GROUP.
        """
        ec_order = _bn_new()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_GROUP_get_order(ec_group, ec_order, bn_ctx)
            backend.openssl_assert(res == 1)
        return ec_order

    @staticmethod
    def _get_ec_generator_by_group(ec_group):
        """
        Returns the generator point of a given curve via its OpenSSL EC_GROUP.
        """
        generator = backend._lib.EC_GROUP_get0_generator(ec_group)
        backend.openssl_assert(generator != backend._ffi.NULL)
        generator = backend._ffi.gc(generator, backend._lib.EC_POINT_clear_free)

        return generator

    @staticmethod
    def _get_ec_group_degree(ec_group):
        """
        Returns the number of bits needed to represent the order of the finite
        field upon the curve is based.
        """
        return backend._lib.EC_GROUP_get_degree(ec_group)

    def __init__(self, nid: int):
        """
        Instantiates an OpenSSL curve with the provided curve_nid and derives
        the proper EC_GROUP struct and order. You can _only_ instantiate curves
        with supported nids (see `Curve.supported_curves`).
        """

        try:
            self.name = self._supported_curves[nid]
        except KeyError:
            raise NotImplementedError("Curve NID {} is not supported.".format(nid))

        self.nid = nid

        self.ec_group = self._get_ec_group_by_curve_nid(self.nid)
        self.bn_order = self._get_ec_order_by_group(self.ec_group)
        self.point_generator = self._get_ec_generator_by_group(self.ec_group)

        size_in_bits = self._get_ec_group_degree(self.ec_group)
        self.field_element_size = (size_in_bits + 7) // 8

        self.scalar_size = _bn_size(self.bn_order)
        self.order = bn_to_int(self.bn_order)

    @classmethod
    def from_name(cls, name: str) -> 'Curve':
        """
        Alternate constructor to generate a curve instance by its name.

        Raises NotImplementedError if the name cannot be mapped to a known
        supported curve NID.
        """

        name = name.casefold()  # normalize

        for supported_nid, supported_name in cls._supported_curves.items():
            if name == supported_name:
                instance = cls(nid=supported_nid)
                break
        else:
            raise NotImplementedError(f"{name} is not supported curve name.")

        return instance

    def __eq__(self, other):
        return self.nid == other.nid

    def __str__(self):
        return "<OpenSSL Curve(nid={}, name={})>".format(self.nid, self.name)


#
# OpenSSL bignums
#


def _bn_new(set_consttime_flag=True):
    """
    Returns a new and initialized OpenSSL BIGNUM.
    The set_consttime_flag is set to True by default. When this instance of a
    CurveBN object has BN_FLG_CONSTTIME set, OpenSSL will use constant time
    operations whenever this CurveBN is passed.
    """
    new_bn = backend._lib.BN_new()
    backend.openssl_assert(new_bn != backend._ffi.NULL)
    new_bn = backend._ffi.gc(new_bn, backend._lib.BN_clear_free)

    if set_consttime_flag:
        backend._lib.BN_set_flags(new_bn, backend._lib.BN_FLG_CONSTTIME)
    return new_bn


def bn_is_normalized(check_bn, modulus):
    """
    Returns ``True`` if ``check_bn`` is in ``[0, modulus)``, ``False`` otherwise.
    """
    zero = backend._int_to_bn(0)
    zero = backend._ffi.gc(zero, backend._lib.BN_clear_free)

    check_sign = backend._lib.BN_cmp(check_bn, zero)
    range_check = backend._lib.BN_cmp(check_bn, modulus)
    return (check_sign == 1 or check_sign == 0) and range_check == -1


def bn_from_int(py_int: int, modulus=None, set_consttime_flag=True):
    """
    Converts the given Python int to an OpenSSL BIGNUM. If ``modulus`` is
    provided, it will check if the Python integer is within ``[0, modulus)``.

    If set_consttime_flag is set to True, OpenSSL will use constant time
    operations when using this CurveBN.
    """
    conv_bn = backend._int_to_bn(py_int)
    conv_bn = backend._ffi.gc(conv_bn, backend._lib.BN_clear_free)

    if modulus and not bn_is_normalized(conv_bn, modulus):
        raise ValueError("The Python integer given is not under the provided modulus.")

    if set_consttime_flag:
        backend._lib.BN_set_flags(conv_bn, backend._lib.BN_FLG_CONSTTIME)
    return conv_bn


def bn_from_bytes(bytes_seq: bytes, set_consttime_flag=True, modulus=None):
    """
    Converts the given byte sequence to an OpenSSL BIGNUM.
    If set_consttime_flag is set to True, OpenSSL will use constant time
    operations when using this BIGNUM.
    """
    bn = _bn_new(set_consttime_flag)
    backend._lib.BN_bin2bn(bytes_seq, len(bytes_seq), bn)
    backend.openssl_assert(bn != backend._ffi.NULL)

    if modulus:
        bignum =_bn_new()
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_mod(bignum, bn, modulus, bn_ctx)
            backend.openssl_assert(res == 1)

    return bn


def bn_to_bytes(bn, length: int):
    """
    Converts the given OpenSSL BIGNUM into a Python bytes sequence.
    If length is given, the return bytes will have such length.
    If the BIGNUM doesn't fit, it raises a ValueError.
    """

    # Sanity check, CurveScalar ensures it won't happen.
    bn_num_bytes = backend._lib.BN_num_bytes(bn)
    assert bn_num_bytes <= length, f"Input BIGNUM doesn't fit in {length} B"

    bin_ptr = backend._ffi.new("unsigned char []", length)
    bin_len = backend._lib.BN_bn2bin(bn, bin_ptr)
    return bytes.rjust(backend._ffi.buffer(bin_ptr, bin_len)[:], length, b'\0')


def bn_random_nonzero(modulus):

    one = backend._lib.BN_value_one()

    # TODO: in most cases, we want this number to be secret.
    # OpenSSL 1.1.1 has `BN_priv_rand_range()`, but it is not
    # currently exported by `cryptography`.
    # Use when available.

    # Calculate `modulus - 1`
    modulus_minus_1 = _bn_new()
    res = backend._lib.BN_sub(modulus_minus_1, modulus, one)
    backend.openssl_assert(res == 1)

    # Get a random in range `[0, modulus - 1)`
    new_rand_bn = _bn_new()
    res = backend._lib.BN_rand_range(new_rand_bn, modulus_minus_1)
    backend.openssl_assert(res == 1)

    # Turn it into a random in range `[1, modulus)`
    op_sum = _bn_new()
    res = backend._lib.BN_add(op_sum, new_rand_bn, one)
    backend.openssl_assert(res == 1)

    return op_sum


def _bn_size(bn):
    return backend._lib.BN_num_bytes(bn)


def bn_to_int(bn):
    return backend._bn_to_int(bn)


def bn_cmp(bn1, bn2):
    # -1 less than, 0 is equal to, 1 is greater than
    return backend._lib.BN_cmp(bn1, bn2)


def bn_one():
    return backend._lib.BN_value_one()


def bn_is_zero(bn):
    # No special function exported in the current backend, so this will have to do
    return bn_cmp(bn, bn_from_int(0)) == 0


def bn_invert(bn, modulus):
    with backend._tmp_bn_ctx() as bn_ctx:
        inv = backend._lib.BN_mod_inverse(backend._ffi.NULL, bn, modulus, bn_ctx)
        backend.openssl_assert(inv != backend._ffi.NULL)
        inv = backend._ffi.gc(inv, backend._lib.BN_clear_free)
    return inv


def bn_sub(bn1, bn2, modulus):
    diff = _bn_new()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod_sub(diff, bn1, bn2, modulus, bn_ctx)
        backend.openssl_assert(res == 1)
    return diff


def bn_add(bn1, bn2, modulus):
    op_sum = _bn_new()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod_add(op_sum, bn1, bn2, modulus, bn_ctx)
        backend.openssl_assert(res == 1)
    return op_sum


def bn_mul(bn1, bn2, modulus):
    product = _bn_new()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod_mul(product, bn1, bn2, modulus, bn_ctx)
        backend.openssl_assert(res == 1)
    return product


def bn_to_privkey(curve: Curve, bn):

    ec_key = backend._lib.EC_KEY_new()
    backend.openssl_assert(ec_key != backend._ffi.NULL)
    ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

    set_group_result = backend._lib.EC_KEY_set_group(ec_key, curve.ec_group)
    backend.openssl_assert(set_group_result == 1)

    set_privkey_result = backend._lib.EC_KEY_set_private_key(ec_key, bn)
    backend.openssl_assert(set_privkey_result == 1)

    evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
    return _EllipticCurvePrivateKey(backend, ec_key, evp_pkey)


#
# OpenSSL EC points
#


def _point_new(ec_group):
    """
    Returns a new and initialized OpenSSL EC_POINT given the group of a curve.
    If __curve_nid is provided, it retrieves the group from the curve provided.
    """
    new_point = backend._lib.EC_POINT_new(ec_group)
    backend.openssl_assert(new_point != backend._ffi.NULL)
    new_point = backend._ffi.gc(new_point, backend._lib.EC_POINT_clear_free)

    return new_point


def point_from_affine_coords(curve: Curve, affine_x: int, affine_y: int):
    """
    Returns an EC_POINT given the group of a curve and the affine coordinates
    provided.
    """
    bn_affine_x = bn_from_int(affine_x)
    bn_affine_y = bn_from_int(affine_y)

    new_point = _point_new(curve.ec_group)
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_set_affine_coordinates_GFp(
            curve.ec_group, new_point, bn_affine_x, bn_affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)
    return new_point


def point_to_affine_coords(curve: Curve, point) -> Tuple[int, int]:
    """
    Returns the affine coordinates of a given point on the provided ec_group.
    """
    affine_x = _bn_new()
    affine_y = _bn_new()

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_get_affine_coordinates_GFp(
            curve.ec_group, point, affine_x, affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return bn_to_int(affine_x), bn_to_int(affine_y)


class ErrorInvalidCompressedPoint(Exception):
    pass


class ErrorInvalidPointEncoding(Exception):
    pass


def point_from_bytes(curve: Curve, data):
    point = _point_new(curve.ec_group)
    try:
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.EC_POINT_oct2point(curve.ec_group, point, data, len(data), bn_ctx);
            backend.openssl_assert(res == 1)
    except InternalError as e:
        # We want to catch specific InternalExceptions.
        # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h
        # There is also EC_R_POINT_IS_NOT_ON_CURVE (code 107),
        # but somehow it is never triggered during deserialization.
        if e.err_code[0].reason == 110: # EC_R_INVALID_COMPRESSED_POINT
            raise ErrorInvalidCompressedPoint
        elif e.err_code[0].reason == 102: # EC_R_INVALID_ENCODING
            raise ErrorInvalidPointEncoding
        else:
            # Any other exception, we raise it.
            # (although at the moment I'm not sure what should one do to cause it)
            raise e # pragma: no cover
    return point


def point_to_bytes_compressed(curve: Curve, point):
    point_conversion_form = backend._lib.POINT_CONVERSION_COMPRESSED

    size = curve.field_element_size + 1 # compressed point size

    bin_ptr = backend._ffi.new("unsigned char[]", size)
    with backend._tmp_bn_ctx() as bn_ctx:
        bin_len = backend._lib.EC_POINT_point2oct(
            curve.ec_group, point, point_conversion_form,
            bin_ptr, size, bn_ctx
        )
        backend.openssl_assert(bin_len != 0)

    return bytes(backend._ffi.buffer(bin_ptr, bin_len)[:])


def point_eq(curve: Curve, point1, point2):
    with backend._tmp_bn_ctx() as bn_ctx:
        is_equal = backend._lib.EC_POINT_cmp(curve.ec_group, point1, point2, bn_ctx)
        backend.openssl_assert(is_equal != -1)

    # 1 is not-equal, 0 is equal, -1 is error
    return is_equal == 0


def point_mul_bn(curve: Curve, point, bn):
    prod = _point_new(curve.ec_group)
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_mul(curve.ec_group, prod, backend._ffi.NULL, point, bn, bn_ctx)
        backend.openssl_assert(res == 1)
    return prod


def point_add(curve: Curve, point1, point2):
    op_sum = _point_new(curve.ec_group)
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_add(curve.ec_group, op_sum, point1, point2, bn_ctx)
        backend.openssl_assert(res == 1)
    return op_sum


def point_neg(curve: Curve, point):
    inv = backend._lib.EC_POINT_dup(point, curve.ec_group)
    backend.openssl_assert(inv != backend._ffi.NULL)
    inv = backend._ffi.gc(inv, backend._lib.EC_POINT_clear_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_invert(curve.ec_group, inv, bn_ctx)
        backend.openssl_assert(res == 1)

    return inv


def point_to_pubkey(curve: Curve, point):

    ec_key = backend._lib.EC_KEY_new()
    backend.openssl_assert(ec_key != backend._ffi.NULL)
    ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

    set_group_result = backend._lib.EC_KEY_set_group(ec_key, curve.ec_group)
    backend.openssl_assert(set_group_result == 1)

    set_pubkey_result = backend._lib.EC_KEY_set_public_key(ec_key, point)
    backend.openssl_assert(set_pubkey_result == 1)

    evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
    return _EllipticCurvePublicKey(backend, ec_key, evp_pkey)
