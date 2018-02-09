from cryptography.exceptions import InternalError
from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve
from umbral.point import Point

curve = default_curve() or ec.SECP256K1()
RANDOM_K256_POINT = Point.gen_rand(curve)
RANDOM_K256_POINT2 = Point.gen_rand(curve)
RANDOM_K256_BIGNUM = BigNum.gen_rand(curve)


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
    """http://www.secg.org/SEC2-Ver-1.0.pdf Section 2.7.1"""
    g1 = Point.get_generator_from_curve(curve)

    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')

    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed, curve)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed, curve)
    assert g1 == g3
    assert g2 == g3
