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

    actual_mod_inverse = backend._lib.BN_mod_inverse

    def check_bignum_ctypes(*bignums):
        for bn in bignums:
            assert 'BIGNUM' in str(bn)
            assert bn.__class__.__name__ == 'CDataGCP'

    def check_point_ctypes(*ec_points):
        for point in ec_points:
            assert 'EC_POINT' in str(point)

    @contextlib.contextmanager
    def mocked_openssl_backend():
        def mocked_ec_point_equality(group, ec_point, other_point, context):
            assert 'BN_CTX' in str(context)
            assert 'EC_GROUP' in str(group)
            check_point_ctypes(ec_point, other_point)

            assert random_ec_point1.group == group

            assert random_ec_point1.ec_point == ec_point
            assert random_ec_point1.ec_point == other_point
            return 1    # always succeed

        def mocked_ec_point_addition(group, sum, ec_point, other_point, context):
            assert 'BN_CTX' in str(context)
            check_point_ctypes(sum, other_point)

            assert random_ec_point1.group == group
            assert random_ec_point1.ec_point == ec_point
            return 1    # always succeed

        def mocked_ec_point_multiplication(group, product, null, ec_point, bignum, context):
            assert 'BN_CTX' in str(context)
            check_point_ctypes(ec_point, product)
            assert 'EC_GROUP' in str(group)
            assert 'NULL' in str(null)

            assert random_ec_point1.group == group
            assert random_ec_point1.ec_point == ec_point
            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum1.curve_nid == random_ec_point1.curve_nid
            return 1    # always succeed

        def mocked_ec_point_inversion(group, inverse, context):
            assert 'BN_CTX' in str(context)
            check_point_ctypes(inverse)

            assert random_ec_point1.group == group
            return 1    # always succeed

        def mocked_bn_compare(bignum, other):
            check_bignum_ctypes(bignum, other)
            assert random_ec_bignum1.bignum == bignum
            return 1    # always succeed

        def mocked_bn_mod_exp(power, bignum, other, order, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, other, power, order)

            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum2.bignum == other
            return 1    # always succeed

        def mocked_bn_mod_mul(product, bignum, other, order, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, other, product, order)

            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum2.bignum == other
            return 1    # always succeed

        def mocked_bn_inverse(null, bignum, order, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, order)
            assert 'NULL' in str(null)

            assert random_ec_bignum1.bignum == bignum
            return actual_mod_inverse(null, bignum, order, context)    # patched to original call

        def mocked_bn_add(sum, bignum, other, order, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, other, sum, order)

            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum2.bignum == other
            return 1    # always succeed

        def mocked_bn_sub(diff, bignum, other, order, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, other, diff, order)

            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum2.bignum == other
            return 1    # always succeed

        def mocked_bn_nmod(rem, bignum, other, context):
            assert 'BN_CTX' in str(context)
            check_bignum_ctypes(bignum, other, rem)

            assert random_ec_bignum1.bignum == bignum
            assert random_ec_bignum2.bignum == other
            return 1    # always succeed

        mock_load = {
                     # Point
                     'EC_POINT_mul': mocked_ec_point_multiplication,
                     'EC_POINT_cmp': mocked_ec_point_equality,
                     'EC_POINT_add': mocked_ec_point_addition,
                     'EC_POINT_invert': mocked_ec_point_inversion,

                     # Bignum
                     'BN_cmp': mocked_bn_compare,
                     'BN_mod_exp': mocked_bn_mod_exp,
                     'BN_mod_mul': mocked_bn_mod_mul,
                     'BN_mod_inverse': mocked_bn_inverse,
                     'BN_mod_add': mocked_bn_add,
                     'BN_mod_sub': mocked_bn_sub,
                     'BN_nnmod': mocked_bn_nmod,
                    }

        with contextlib.ExitStack() as stack:
            for method, patch in mock_load.items():
                stack.enter_context(mocker.mock_module.patch.object(backend._lib, method, patch))
            yield

    return mocked_openssl_backend
