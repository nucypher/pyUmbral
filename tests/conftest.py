import contextlib

import pytest
from cryptography.hazmat.backends.openssl import backend

from umbral.bignum import BigNum
from umbral.point import Point


@pytest.fixture()
def random_ec_point1():
    yield Point.gen_rand()


@pytest.fixture()
def random_ec_point2():
    yield Point.gen_rand()


@pytest.fixture()
def random_ec_bignum1():
    yield BigNum.gen_rand()


@pytest.fixture()
def random_ec_bignum2():
    yield BigNum.gen_rand()


@pytest.fixture()
def mock_openssl(mocker, random_ec_point1: Point, random_ec_bignum1: BigNum, random_ec_bignum2: BigNum):
    """
    Patches openssl backend methods for testing.
    For all functions, 1 is returned for success, 0 on error.

    """

    actual_backend = {
        # Point
        'EC_POINT_mul': backend._lib.EC_POINT_mul,
        'EC_POINT_cmp': backend._lib.EC_POINT_cmp,
        'EC_POINT_add': backend._lib.EC_POINT_add,
        'EC_POINT_invert': backend._lib.EC_POINT_invert,

        # Bignum
        'BN_cmp': backend._lib.BN_cmp,
        'BN_mod_exp': backend._lib.BN_mod_exp,
        'BN_mod_mul': backend._lib.BN_mod_mul,
        'BN_mod_inverse': backend._lib.BN_mod_inverse,
        'BN_mod_add': backend._lib.BN_mod_add,
        'BN_mod_sub': backend._lib.BN_mod_sub,
        'BN_nnmod': backend._lib.BN_nnmod,
    }

    def check_bignum_ctypes(*bignums):
        for bn in bignums:
            assert 'BIGNUM' in str(bn)
            assert bn.__class__.__name__ == 'CDataGCP'

    def check_point_ctypes(*ec_points):
        for point in ec_points:
            assert 'EC_POINT' in str(point)
            assert point.__class__.__name__ == 'CDataGCP'

    @contextlib.contextmanager
    def mocked_openssl_backend():
        def mocked_ec_point_equality(group, ec_point, other_point, context):
            check_point_ctypes(ec_point, other_point)
            assert 'BN_CTX' in str(context)
            assert 'EC_GROUP' in str(group)
            assert random_ec_point1.group == group
            assert not bool(actual_backend['EC_POINT_cmp'](group, random_ec_point1.ec_point, ec_point, context))
            result = actual_backend['EC_POINT_cmp'](group, random_ec_point1.ec_point, other_point, context)
            assert not bool(result)
            return result

        def mocked_ec_point_addition(group, sum, ec_point, other_point, context):
            check_point_ctypes(sum, other_point)
            assert 'BN_CTX' in str(context)
            assert random_ec_point1.group == group
            assert not bool(actual_backend['EC_POINT_cmp'](group, random_ec_point1.ec_point, ec_point, context))
            return actual_backend['EC_POINT_add'](group, sum, ec_point, other_point, context)

        def mocked_ec_point_multiplication(group, product, null, ec_point, bignum, context):
            check_point_ctypes(ec_point, product)
            assert 'BN_CTX' in str(context)
            assert 'EC_GROUP' in str(group)
            assert 'NULL' in str(null)
            assert random_ec_point1.group == group
            assert random_ec_bignum1.curve_nid == random_ec_point1.curve_nid
            assert not bool(actual_backend['EC_POINT_cmp'](group, random_ec_point1.ec_point, ec_point, context))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            return actual_backend['EC_POINT_mul'](group, product, null, ec_point, bignum, context)

        def mocked_ec_point_inversion(group, inverse, context):
            check_point_ctypes(inverse)
            assert 'BN_CTX' in str(context)
            assert random_ec_point1.group == group
            return actual_backend['EC_POINT_invert'](group, inverse, context)

        def mocked_bn_compare(bignum, other):
            check_bignum_ctypes(bignum, other)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            return actual_backend['BN_cmp'](bignum, other)

        def mocked_bn_mod_exponent(power, bignum, other, order, context):
            check_bignum_ctypes(bignum, other, power, order)
            assert 'BN_CTX' in str(context)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum2.bignum, other))
            return actual_backend['BN_mod_exp'](power, bignum, other, order, context)

        def mocked_bn_mod_multiplication(product, bignum, other, order, context):
            check_bignum_ctypes(bignum, other, product, order)
            assert 'BN_CTX' in str(context)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum2.bignum, other))
            return actual_backend['BN_mod_mul'](product, bignum, other, order, context)

        def mocked_bn_inverse(null, bignum, order, context):
            check_bignum_ctypes(bignum, order)
            assert 'BN_CTX' in str(context)
            assert 'NULL' in str(null)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            return actual_backend['BN_mod_inverse'](null, bignum, order, context)

        def mocked_bn_addition(sum, bignum, other, order, context):
            check_bignum_ctypes(bignum, other, sum, order)
            assert 'BN_CTX' in str(context)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum2.bignum, other))
            return actual_backend['BN_mod_add'](sum, bignum, other, order, context)

        def mocked_bn_subtraction(diff, bignum, other, order, context):
            check_bignum_ctypes(bignum, other, diff, order)
            assert 'BN_CTX' in str(context)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum2.bignum, other))
            return actual_backend['BN_mod_sub'](diff, bignum, other, order, context)

        def mocked_bn_nmodulus(rem, bignum, other, context):
            check_bignum_ctypes(bignum, other, rem)
            assert 'BN_CTX' in str(context)
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum1.bignum, bignum))
            assert not bool(actual_backend['BN_cmp'](random_ec_bignum2.bignum, other))
            return actual_backend['BN_nnmod'](rem, bignum, other, context)

        mock_load = {
                     # Point
                     'EC_POINT_mul': mocked_ec_point_multiplication,
                     'EC_POINT_cmp': mocked_ec_point_equality,
                     'EC_POINT_add': mocked_ec_point_addition,
                     'EC_POINT_invert': mocked_ec_point_inversion,

                     # Bignum
                     'BN_cmp': mocked_bn_compare,
                     'BN_mod_exp': mocked_bn_mod_exponent,
                     'BN_mod_mul': mocked_bn_mod_multiplication,
                     'BN_mod_inverse': mocked_bn_inverse,
                     'BN_mod_add': mocked_bn_addition,
                     'BN_mod_sub': mocked_bn_subtraction,
                     'BN_nnmod': mocked_bn_nmodulus,
                    }

        with contextlib.ExitStack() as stack:
            for method, patch in mock_load.items():
                stack.enter_context(mocker.mock_module.patch.object(backend._lib, method, patch))
            yield

    return mocked_openssl_backend
