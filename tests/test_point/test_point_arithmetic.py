import contextlib

import pytest
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve
from umbral.point import Point

curve = default_curve() or ec.SECP256K1()


@pytest.fixture()
def mock_openssl(mocker, random_ec_point1, random_ec_bignum):
    @contextlib.contextmanager
    def mocked_openssl_backend():
        def mocked_ec_point_equality(group, ec_point, other_point, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_GROUP' in str(group)
            assert 'EC_POINT' in str(ec_point)
            assert 'EC_POINT' in str(other_point)

            assert random_ec_point1.group == group
            assert random_ec_point1.ec_point == ec_point
            assert random_ec_point1.ec_point == other_point

            return 1

        def mocked_ec_point_addition(group, sum, ec_point, other_point, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_POINT' in str(other_point)
            assert 'EC_POINT' in str(sum)

            assert random_ec_point1.group == group
            assert random_ec_point1.ec_point == ec_point

            return 1

        def mocked_ec_point_multiplication(group, product, null, ec_point, bignum, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_GROUP' in str(group)
            assert 'EC_POINT' in str(ec_point)
            assert 'EC_POINT' in str(product)
            assert 'NULL' in str(null)

            assert random_ec_point1.group == group
            assert random_ec_point1.ec_point == ec_point

            assert random_ec_bignum.bignum == bignum
            assert random_ec_bignum.curve_nid == random_ec_point1.curve_nid

            return 1

        def mocked_ec_point_inversion(group, inverse, bn_ctx):
            assert 'EC_POINT' in str(inverse)
            assert 'BN_CTX' in str(bn_ctx)

            assert random_ec_point1.group == group

            return 1

        mock_load = {'EC_POINT_mul': mocked_ec_point_multiplication,
                     'EC_POINT_cmp': mocked_ec_point_equality,
                     'EC_POINT_add': mocked_ec_point_addition,
                     'EC_POINT_invert': mocked_ec_point_inversion}

        with contextlib.ExitStack() as stack:
            for method, patch in mock_load.items():
                stack.enter_context(mocker.mock_module.patch.object(backend._lib, method, patch))
            yield

    return mocked_openssl_backend


def test_mocked_openssl_point_arithmetic(mock_openssl, random_ec_point1, random_ec_point2, random_ec_bignum):
    with mock_openssl():
        _ = random_ec_point1 == random_ec_point1   # __eq__
        _ = random_ec_point1 * random_ec_bignum    # __mul__
        _ = random_ec_point1 + random_ec_point2    # __add__
        _ = ~random_ec_point1                      # __invert__


def test_point_curve_mult_regression():
    k256_point_bytes = b'\x03\xe0{\x1bQ\xbf@\x1f\x95\x8d\xe1\x17\xa7\xbe\x9e-G`T\xbf\xd7\x9e\xa7\x10\xc8uA\xc0z$\xc0\x92\x8a'
    k256_bn_bytes = b'4u\xd70-\xa0h\xdeG\xf0\x143\x06!\x91\x05{\xe4jC\n\xf1h\xed7a\xf8\x9d\xec^\x19\x8c'

    k256_point = Point.from_bytes(k256_point_bytes, curve=curve)
    k256_bn = BigNum.from_bytes(k256_bn_bytes, curve=curve)

    product_with_star_operator = k256_point * k256_bn

    # Make sure we have instantiated a new, unequal point in the same curve and group
    assert isinstance(product_with_star_operator, Point), "Point.__mul__ did not return a point instance"
    assert k256_point != product_with_star_operator
    assert k256_point.curve_nid == product_with_star_operator.curve_nid
    assert k256_point.group == product_with_star_operator.group

    product_bytes = b'\x03\xc9\xda\xa2\x88\xe2\xa0+\xb1N\xb6\xe6\x1c\xa5(\xe6\xe0p\xf6\xf4\xa9\xfc\xb1\xfaUV\xd3\xb3\x0e4\x94\xbe\x12'
    product_point = Point.from_bytes(product_bytes)
    assert product_with_star_operator.to_bytes() == product_bytes
    assert product_point == product_with_star_operator

    # Repeating the operation, should return the same result.
    product_with_star_operator_again = k256_point * k256_bn
    assert product_with_star_operator == product_with_star_operator_again
