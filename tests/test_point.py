import contextlib

import pytest
from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve
from umbral.point import Point

curve = default_curve() or ec.SECP256K1()
RANDOM_K256_POINT = Point.gen_rand(curve)
RANDOM_K256_POINT2 = Point.gen_rand(curve)
RANDOM_K256_BIGNUM = BigNum.gen_rand(curve)


@pytest.fixture()
def mock_openssl(mocker):
    @contextlib.contextmanager
    def mocked_openssl_backend():
        def mocked_ec_point_equality(group, ec_point, other_point, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_GROUP' in str(group)
            assert 'EC_POINT' in str(ec_point)
            assert 'EC_POINT' in str(other_point)

            assert RANDOM_K256_POINT.group == group
            assert RANDOM_K256_POINT.ec_point == ec_point
            assert RANDOM_K256_POINT.ec_point == other_point

            return 1

        def mocked_ec_point_addition(group, sum, ec_point, other_point, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_POINT' in str(other_point)
            assert 'EC_POINT' in str(sum)

            assert RANDOM_K256_POINT.group == group
            assert RANDOM_K256_POINT.ec_point == ec_point

            return 1

        def mocked_ec_point_multiplication(group, product, null, ec_point, bignum, bn_ctx):
            assert 'BN_CTX' in str(bn_ctx)
            assert 'EC_GROUP' in str(group)
            assert 'EC_POINT' in str(ec_point)
            assert 'EC_POINT' in str(product)
            assert 'NULL' in str(null)

            assert RANDOM_K256_POINT.group == group
            assert RANDOM_K256_POINT.ec_point == ec_point

            assert RANDOM_K256_BIGNUM.bignum == bignum
            assert RANDOM_K256_BIGNUM.curve_nid == RANDOM_K256_POINT.curve_nid

            return 1

        def mocked_ec_point_inversion(group, inverse, bn_ctx):
            assert 'EC_POINT' in str(inverse)
            assert 'BN_CTX' in str(bn_ctx)

            assert RANDOM_K256_POINT.group == group

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


def test_mocked_point_curve_arithmetic(mock_openssl):
    with mock_openssl():
        _ = RANDOM_K256_POINT == RANDOM_K256_POINT     # __eq__
        _ = RANDOM_K256_POINT * RANDOM_K256_BIGNUM     # __mul__
        _ = RANDOM_K256_POINT + RANDOM_K256_POINT2     # __add__
        _ = ~RANDOM_K256_POINT                         # __invert__


def test_from_to_bytes():

    p = Point.gen_rand(curve)
    pbytes = p.to_bytes(is_compressed=False)
    q = Point.from_bytes(pbytes, curve)
    assert p == q

    pbytes = p.to_bytes(is_compressed=True)
    q = Point.from_bytes(pbytes, curve)
    assert p == q


def test_point_to_cryptography_pubkey():
    p = Point.gen_rand(curve)

    crypto_pub_key = p.to_cryptography_pub_key()

    p_affine = p.to_affine()
    crypto_affine = (
        crypto_pub_key.public_numbers().x,
        crypto_pub_key.public_numbers().y
    )

    assert p_affine == crypto_affine


def test_invalid_points():
    p = Point.gen_rand(curve)

    pbytes = bytearray(p.to_bytes(is_compressed=False))
    # Flips last bit
    pbytes[-1] = pbytes[-1] ^ 0x01
    pbytes = bytes(pbytes)

    try:
        q = Point.from_bytes(pbytes, curve)
    except InternalError as e:
        # We want to catch specific InternalExceptions: 
        # - Point not in the curve (code 107)
        # - Invalid compressed point (code 110)
        # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
        if e.err_code[0].reason in (107, 110):
            pass
        else:
            assert False
    else:
        assert False


def test_generator_point():
    g1 = Point.get_generator_from_curve(curve)

    # http://www.secg.org/SEC2-Ver-1.0.pdf
    # Section 2.7.1
    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')

    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed, curve)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed, curve)
    assert g1 == g3
    assert g2 == g3


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


