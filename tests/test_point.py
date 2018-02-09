import contextlib
from unittest import mock

from cryptography.exceptions import InternalError

from umbral.bignum import BigNum
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec


from umbral.config import default_curve
import pytest

from umbral.point import Point


@pytest.fixture()
def secp256k1():
    yield ec.SECP256K1()


RANDOM_K256_POINT = Point.gen_rand(ec.SECP256K1())
RANDOM_K256_BIGNUM = BigNum.gen_rand(ec.SECP256K1())


def test_from_to_bytes(secp256k1):

    p = Point.gen_rand(secp256k1)

    pbytes = p.to_bytes(is_compressed=False)
    q = Point.from_bytes(pbytes, secp256k1)

    assert p == q

    pbytes = p.to_bytes(is_compressed=True)
    q = Point.from_bytes(pbytes, secp256k1)

    assert p == q


def test_point_to_cryptography_pubkey(secp256k1):
    p = Point.gen_rand(secp256k1)

    crypto_pub_key = p.to_cryptography_pub_key()

    p_affine = p.to_affine()
    crypto_affine = (
        crypto_pub_key.public_numbers().x,
        crypto_pub_key.public_numbers().y
    )

    assert p_affine == crypto_affine


def test_invalid_points(secp256k1):
    p = Point.gen_rand(secp256k1)

    pbytes = bytearray(p.to_bytes(is_compressed=False))
    # Flips last bit
    pbytes[-1] = pbytes[-1] ^ 0x01
    pbytes = bytes(pbytes)

    try:
        q = Point.from_bytes(pbytes, secp256k1)
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


def test_generator(secp256k1):
    g1 = Point.get_generator_from_curve(secp256k1)

    # http://www.secg.org/SEC2-Ver-1.0.pdf
    # Section 2.7.1
    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')

    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed, secp256k1)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed, secp256k1)
    assert g1 == g3
    assert g2 == g3


def test_mocked_point_curve_mult(mocker):

    @contextlib.contextmanager
    def mocked_openssl_backend():

        def mocked_ec_point_mul(group, product, null, ec_point, bignum, bn_ctx):

            # Point
            assert RANDOM_K256_POINT.group == group
            assert RANDOM_K256_POINT.ec_point == ec_point

            # Bignum
            assert RANDOM_K256_BIGNUM.bignum == bignum
            assert RANDOM_K256_BIGNUM.curve_nid == RANDOM_K256_POINT.curve_nid
            return 1

        with mocker.mock_module.patch.object(backend._lib, 'EC_POINT_mul', mocked_ec_point_mul):
            yield

    with mocked_openssl_backend():
        product = RANDOM_K256_POINT * RANDOM_K256_BIGNUM


def test_point_curve_mult_regression(secp256k1):
    k256_point_bytes = b'\x03\xe0{\x1bQ\xbf@\x1f\x95\x8d\xe1\x17\xa7\xbe\x9e-G`T\xbf\xd7\x9e\xa7\x10\xc8uA\xc0z$\xc0\x92\x8a'
    k256_bn_bytes = b'4u\xd70-\xa0h\xdeG\xf0\x143\x06!\x91\x05{\xe4jC\n\xf1h\xed7a\xf8\x9d\xec^\x19\x8c'

    k256_point = Point.from_bytes(k256_point_bytes, curve=secp256k1)
    k256_bn = BigNum.from_bytes(k256_bn_bytes, curve=secp256k1)

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
