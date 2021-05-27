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


def test_to_and_from_affine():

    x = 17004608369308732328368332205668001941491834793934321461466076545247324070015
    y = 69725941631324401609944843130171147910924748427773762412028916504484868631573

    p = CurvePoint.from_affine(x, y)

    assert p.to_affine() == (x, y)


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


def test_coords_with_special_characteristics():

    # Testing that a point with x coordinate greater than the curve order is still valid.
    # In particular, we will test the last valid point from the default curve (secp256k1)
    # whose x coordinate is `field_order - 3` and is greater than the order of the curve

    field_order = 2**256 - 0x1000003D1
    compressed = b'\x02' + (field_order-3).to_bytes(32, 'big')

    last_point = CurvePoint.from_bytes(compressed)

    # The same point, but obtained through the from_affine method
    x = 115792089237316195423570985008687907853269984665640564039457584007908834671660
    y = 109188863561374057667848968960504138135859662956057034999983532397866404169138

    assert last_point == CurvePoint.from_affine(x, y)
