import pytest
from cryptography.exceptions import InternalError
from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve
from umbral.point import Point


def test_generate_random_points():
    for _ in range(10):
        point = Point.gen_rand()
        another_point = Point.gen_rand()
        assert isinstance(point, Point)
        assert isinstance(another_point, Point)
        assert point != another_point


def test_bytes_serializers(random_ec_point1):

    curve = ec.SECP256K1
    point_bytes = random_ec_point1.to_bytes()

    point_with_nid = Point.from_bytes(point_bytes, curve=714)         # from nid
    assert isinstance(point_with_nid, Point)

    point_with_curve = Point.from_bytes(point_bytes, curve=curve)     # from curve
    assert isinstance(point_with_nid, Point)

    assert point_with_nid == point_with_curve

    point = point_with_curve
    the_same_point_bytes = point.to_bytes(is_compressed=False)
    assert point_bytes == the_same_point_bytes

    malformed_point_bytes = point_bytes + b'0x'
    with pytest.raises(ValueError):
        _ = Point.from_bytes(malformed_point_bytes)


def test_affine_deserializer():
    affine = (54495335564072000415434275044935054036617226655045445809732056033758606213450,
              26274482902044210718566767736429706729731617411738990314884135712590488065008)

    curve = ec.SECP256K1
    point = Point.from_affine(affine, curve=714)              # from nid
    the_same_point = Point.from_affine(affine, curve=curve)   # from curve instance

    assert point == the_same_point
    assert isinstance(point, Point), 'affine deserializer did not return a Point'


def test_point_to_cryptography_pubkey():
    p = Point.gen_rand()

    crypto_pub_key = p.to_cryptography_pub_key()

    p_affine = p.to_affine()
    crypto_affine = (
        crypto_pub_key.public_numbers().x,
        crypto_pub_key.public_numbers().y
    )

    assert p_affine == crypto_affine


def test_invalid_points():
    p = Point.gen_rand()

    pbytes = bytearray(p.to_bytes(is_compressed=False))
    # Flips last bit
    pbytes[-1] = pbytes[-1] ^ 0x01
    pbytes = bytes(pbytes)

    try:
        q = Point.from_bytes(pbytes)
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
    g1 = Point.get_generator_from_curve()

    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')

    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed)
    assert g1 == g3
    assert g2 == g3
