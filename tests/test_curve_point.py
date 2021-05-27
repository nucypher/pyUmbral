import pytest

from umbral.openssl import ErrorInvalidCompressedPoint, ErrorInvalidPointEncoding
from umbral.curve_point import CurvePoint
from umbral.curve import CURVE


def test_random():
    p1 = CurvePoint.random()
    p2 = CurvePoint.random()
    assert isinstance(p1, CurvePoint)
    assert isinstance(p2, CurvePoint)
    assert p1 != p2


def test_generator_point():
    """http://www.secg.org/SEC2-Ver-1.0.pdf Section 2.7.1"""
    g1 = CurvePoint.generator()

    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed_bytes = g_compressed.to_bytes(CURVE.field_element_size + 1, byteorder='big')
    g2 = CurvePoint.from_bytes(g_compressed_bytes)

    assert g1 == g2


def test_invalid_serialized_points():

    field_order = 2**256 - 0x1000003D1

    # A point on secp256k1
    x = 17004608369308732328368332205668001941491834793934321461466076545247324070015
    y = 69725941631324401609944843130171147910924748427773762412028916504484868631573

    # Check it
    assert (y**2 - x**3 - 7) % field_order == 0

    # Should load
    point_data = b'\x03' + x.to_bytes(CURVE.field_element_size, 'big')
    p = CurvePoint.from_bytes(point_data)

    # Make it invalid
    bad_x = x - 1
    assert (y**2 - bad_x**3 - 7) % field_order != 0

    bad_x_data = b'\x03' + bad_x.to_bytes(CURVE.field_element_size, 'big')
    with pytest.raises(ErrorInvalidCompressedPoint):
        CurvePoint.from_bytes(bad_x_data)

    # Valid x, invalid prefix
    bad_format = b'\xff' + x.to_bytes(CURVE.field_element_size, 'big')
    with pytest.raises(ErrorInvalidPointEncoding):
        CurvePoint.from_bytes(bad_format)


def test_serialize_point_at_infinity():

    p = CurvePoint.random()
    point_at_infinity = p - p

    bytes_point_at_infinity = bytes(point_at_infinity)
    assert bytes_point_at_infinity == b'\x00'


def test_to_affine():
    p = CurvePoint.generator()
    x_ref = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
    y_ref = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
    assert p.to_affine() == (x_ref, y_ref)


def test_identity_to_affine():
    p = CurvePoint.generator()
    identity = p - p
    with pytest.raises(ValueError):
        identity.to_affine()
