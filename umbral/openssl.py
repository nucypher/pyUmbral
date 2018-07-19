import typing
from contextlib import contextmanager
from cryptography.hazmat.backends.openssl import backend


@typing.no_type_check
def _get_new_BN(set_consttime_flag=True):
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


@typing.no_type_check
def _get_ec_group_by_curve_nid(curve_nid: int):
    """
    Returns the group of a given curve via its OpenSSL nid. This must be freed
    after each use otherwise it leaks memory.
    """
    group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
    backend.openssl_assert(group != backend._ffi.NULL)

    return group


@typing.no_type_check
def _get_ec_order_by_group(ec_group):
    """
    Returns the order of a given curve via its OpenSSL EC_GROUP.
    """
    ec_order = _get_new_BN()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(ec_group, ec_order, bn_ctx)
        backend.openssl_assert(res == 1)
    return ec_order


@typing.no_type_check
def _get_ec_generator_by_group(ec_group):
    """
    Returns the generator point of a given curve via its OpenSSL EC_GROUP.
    """
    generator = backend._lib.EC_GROUP_get0_generator(ec_group)
    backend.openssl_assert(generator != backend._ffi.NULL)
    generator = backend._ffi.gc(generator, backend._lib.EC_POINT_clear_free)

    return generator


@typing.no_type_check
def _get_ec_group_degree(ec_group):
    """
    Returns the number of bits needed to represent the order of the finite 
    field upon the curve is based.
    """
    return backend._lib.EC_GROUP_get_degree(ec_group) 


@typing.no_type_check
def _bn_is_on_curve(check_bn, curve: 'Curve'):
    """
    Checks if a given OpenSSL BIGNUM is within the provided curve's order.
    Returns True if the provided BN is on the curve, or False if the BN is zero
    or not on the curve.
    """
    zero = backend._int_to_bn(0)
    zero = backend._ffi.gc(zero, backend._lib.BN_clear_free)

    check_sign = backend._lib.BN_cmp(check_bn, zero)
    range_check = backend._lib.BN_cmp(check_bn, curve.order)
    return check_sign == 1 and range_check == -1


@typing.no_type_check
def _int_to_bn(py_int: int, curve: 'Curve'=None, set_consttime_flag=True):
    """
    Converts the given Python int to an OpenSSL BIGNUM. If a curve is
    provided, it will check if the Python integer is within the order of that
    curve. If it's not within the order, it will raise a ValueError.

    If set_consttime_flag is set to True, OpenSSL will use constant time
    operations when using this CurveBN.
    """
    conv_bn = backend._int_to_bn(py_int)
    conv_bn = backend._ffi.gc(conv_bn, backend._lib.BN_clear_free)
    
    if curve:
        on_curve = _bn_is_on_curve(conv_bn, curve)
        if not on_curve:
            raise ValueError("The Python integer given is not on the provided curve.")

    if set_consttime_flag:
        backend._lib.BN_set_flags(conv_bn, backend._lib.BN_FLG_CONSTTIME)
    return conv_bn


@typing.no_type_check
def _get_new_EC_POINT(curve: 'Curve'):
    """
    Returns a new and initialized OpenSSL EC_POINT given the group of a curve.
    If __curve_nid is provided, it retrieves the group from the curve provided.
    """
    new_point = backend._lib.EC_POINT_new(curve.ec_group)
    backend.openssl_assert(new_point != backend._ffi.NULL)
    new_point = backend._ffi.gc(new_point, backend._lib.EC_POINT_clear_free)

    return new_point


@typing.no_type_check
def _get_EC_POINT_via_affine(affine_x, affine_y, curve: 'Curve'):
    """
    Returns an EC_POINT given the group of a curve and the affine coordinates
    provided.
    """
    new_point = _get_new_EC_POINT(curve)
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_set_affine_coordinates_GFp(
            curve.ec_group, new_point, affine_x, affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)
    return new_point


@typing.no_type_check
def _get_affine_coords_via_EC_POINT(ec_point, curve: 'Curve'):
    """
    Returns the affine coordinates of a given point on the provided ec_group.
    """
    affine_x = _get_new_BN()
    affine_y = _get_new_BN()

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_get_affine_coordinates_GFp(
            curve.ec_group, ec_point, affine_x, affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)
    return (affine_x, affine_y)


@typing.no_type_check
@contextmanager
def _tmp_bn_mont_ctx(modulus):
    """
    Initializes and returns a BN_MONT_CTX for Montgomery ops.
    Requires a modulus to place in the Montgomery structure.
    """
    bn_mont_ctx = backend._lib.BN_MONT_CTX_new()
    backend.openssl_assert(bn_mont_ctx != backend._ffi.NULL)
    # Don't set the garbage collector. Only free it when the context is done
    # or else you'll get a null pointer error.

    try:
        with backend._tmp_bn_ctx() as bn_ctx:
            res = backend._lib.BN_MONT_CTX_set(bn_mont_ctx, modulus, bn_ctx)
            backend.openssl_assert(res == 1)
            yield bn_mont_ctx
    finally:
        backend._lib.BN_MONT_CTX_free(bn_mont_ctx)
