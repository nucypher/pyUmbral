from cryptography.hazmat.backends.openssl import backend


def _get_new_BN():
    """
    Returns a new and initialized OpenSSL BIGNUM.

    TODO: Add flag for consttime
    """
    new_bn = backend._lib.BN_new()
    backend.openssl_assert(new_bn != backend._ffi.NULL)
    new_bn = backend._ffi.gc(new_bn, backend._lib.BN_clear_free)

    return new_bn


def _get_ec_group_by_curve_nid(curve_nid: int):
    """
    Returns the group of a given curve via its OpenSSL nid.
    """
    group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
    backend.openssl_assert(group != backend._ffi.NULL)

    return group


def _get_ec_order_by_curve_nid(curve_nid: int):
    """
    Returns the order of a given curve via its OpenSSL nid.
    """
    ec_group = _get_ec_group_by_curve_nid(curve_nid)
    ec_order = _get_new_BN()

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(ec_group, ec_order, bn_ctx)
        backend.openssl_assert(res == 1)

    return ec_order


def _get_ec_generator_by_curve_nid(curve_nid: int):
    """
    Returns the generator point of a given curve via its OpenSSL nid.
    """
    ec_group = _get_ec_group_by_curve_nid(curve_nid)

    generator = backend._lib.EC_GROUP_get0_generator(ec_group)
    backend.openssl_assert(generator != backend._ffi.NULL)

    return generator


def _bn_is_on_curve(check_bn, curve_nid: int):
    """
    Checks if a given OpenSSL BIGNUM is within the provided curve's order.
    Returns True if the provided BN is on the curve, or False if the BN is zero
    or not on the curve.
    """
    ec_order = _get_ec_order_by_curve_nid(curve_nid)

    # is_zero workaround since BN_is_zero is not exposed yet.
    is_zero = backend._lib.BN_cmp(check_bn, backend._int_to_bn(0))
    range_check = backend._lib.BN_cmp(check_bn, ec_order)
    return is_zero == 1 and range_check == -1


def _int_to_bn(py_int: int, curve_nid: int=None):
    """
    Converts the given Python int to an OpenSSL BIGNUM. If a curve_nid is
    provided, it will check if the Python integer is within the order of that
    curve. If it's not within the order, it will raise a ValueError.

    TODO: Add flag for consttime
    """
    conv_bn = backend._int_to_bn(py_int)
    conv_bn = backend._ffi.gc(conv_bn, backend._lib.BN_clear_free)
    
    if curve_nid:
        on_curve = _bn_is_on_curve(conv_bn, curve_nid)
        if not on_curve:
            raise ValueError("The Python integer given is not on the provided curve.")
    return conv_bn


def _get_new_EC_POINT(ec_group=None, curve_nid: int=None):
    """
    Returns a new and initialized OpenSSL EC_POINT given the group of a curve.
    If curve_nid is provided, it retrieves the group from the curve provided.
    """
    if curve_nid:
        ec_group = _get_ec_group_by_curve_nid(curve_nid)
    elif not ec_group:
        raise ValueError("No group provided.")

    new_point = backend._lib.EC_POINT_new(ec_group)
    backend.openssl_assert(new_point != backend._ffi.NULL)
    new_point = backend._ffi.gc(new_point, backend._lib.EC_POINT_clear_free)

    return new_point


def _get_EC_POINT_via_affine(affine_x, affine_y, ec_group=None, curve_nid: int=None):
    """
    Returns an EC_POINT given the group of a curve and the affine coordinates
    provided.
    If curve_nid is provided, it retrieves the group from the curve provided.
    """
    if curve_nid:
        ec_group = _get_ec_group_by_curve_nid(curve_nid)
    elif not ec_group:
        raise ValueError("No group provided.")

    new_point = _get_new_EC_POINT(ec_group=ec_group)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_set_affine_coordinates_GFp(
            ec_group, new_point, affine_x, affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)
    return new_point


def _get_affine_coords_via_EC_POINT(ec_point, ec_group=None, curve_nid: int=None):
    """
    Returns the affine coordinates of a given point on the provided ec_group.
    If curve_nid is provided, it retrieves the group from the curve provided.
    """
    if curve_nid:
        ec_group = _get_ec_group_by_curve_nid(curve_nid)
    elif not ec_group:
        raise ValueError("No group provided.")

    affine_x = _get_new_BN()
    affine_y = _get_new_BN()

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_get_affine_coordinates_GFp(
            ec_group, ec_point, affine_x, affine_y, bn_ctx
        )
        backend.openssl_assert(res == 1)
    return (affine_x, affine_y)
