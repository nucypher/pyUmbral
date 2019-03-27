"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import pytest
from cryptography.exceptions import InternalError

from umbral.curve import SECP256K1, SECP256R1
from umbral.point import Point


def generate_test_points_bytes(quantity=2):
    points_bytes = [
        (SECP256K1, 714, b'\x02x{DR\x94\x8f\x17\xb8\xa2\x14t\x11\xdb\xb1VK\xdb\xc2\xa0T\x97iCK\x8cz~\xea\xa3\xb7AJ'),
    ]
    for _ in range(quantity):
        args = (SECP256K1, 714, Point.gen_rand(curve=SECP256K1).to_bytes())
        points_bytes.append(args)
    return points_bytes


def generate_test_points_affine(quantity=2):
    points_affine = [
        (SECP256K1, 714, (54495335564072000415434275044935054036617226655045445809732056033758606213450,
                            26274482902044210718566767736429706729731617411738990314884135712590488065008)),
    ]
    for _ in range(quantity):
        args = (SECP256K1, 714, Point.gen_rand(curve=SECP256K1).to_affine())
        points_affine.append(args)
    return points_affine


def test_generate_random_points():
    for _ in range(10):
        point = Point.gen_rand()
        another_point = Point.gen_rand()
        assert isinstance(point, Point)
        assert isinstance(another_point, Point)
        assert point != another_point


@pytest.mark.parametrize("curve, nid, point_bytes", generate_test_points_bytes())
def test_bytes_serializers(point_bytes, nid, curve):
    point_with_curve = Point.from_bytes(point_bytes, curve=curve) # from curve
    assert isinstance(point_with_curve, Point)

    the_same_point_bytes = point_with_curve.to_bytes()
    assert point_bytes == the_same_point_bytes

    representations = (point_bytes, # Compressed representation
                       point_with_curve.to_bytes(is_compressed=False)) # Uncompressed

    for point_representation in representations:

        malformed_point_bytes = point_representation + b'0x'
        with pytest.raises(InternalError):
            _ = Point.from_bytes(malformed_point_bytes)

        malformed_point_bytes = point_representation[1:]
        with pytest.raises(InternalError):
            _ = Point.from_bytes(malformed_point_bytes)

        malformed_point_bytes = point_representation[:-1]
        with pytest.raises(InternalError):
            _ = Point.from_bytes(malformed_point_bytes)


@pytest.mark.parametrize("curve, nid, point_affine", generate_test_points_affine())
def test_affine(point_affine, nid, curve):
    point = Point.from_affine(point_affine, curve=curve)  # from curve
    assert isinstance(point, Point)
    point_affine2 = point.to_affine()
    assert point_affine == point_affine2


def test_invalid_points(random_ec_point2):

    point_bytes = bytearray(random_ec_point2.to_bytes(is_compressed=False))
    point_bytes[-1] = point_bytes[-1] ^ 0x01        # Flips last bit
    point_bytes = bytes(point_bytes)

    with pytest.raises(InternalError) as e:
        _point = Point.from_bytes(point_bytes)

    # We want to catch specific InternalExceptions:
    # - Point not in the curve (code 107)
    # - Invalid compressed point (code 110)
    # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
    assert e.value.err_code[0].reason in (107, 110)


def test_generator_point():
    """http://www.secg.org/SEC2-Ver-1.0.pdf Section 2.7.1"""
    g1 = Point.get_generator_from_curve()

    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed)
    assert g1 == g3
    assert g2 == g3


def test_point_not_on_curve():
    """
    We want to be unable to create a Point that's not on the curve.

    When we try, we get cryptography.exceptions.InternalError - is that specifically because it isn't
    on the curve?  It seems to be reliably raised in the event of the Point being off the curve.

    The OpenSSL docs don't explicitly say that they raise an error for this reason:
    https://www.openssl.org/docs/man1.1.0/crypto/EC_GFp_simple_method.html
    """
    point_on_koblitz256_but_not_P256 = Point.from_bytes(b'\x03%\x98Dk\x88\xe2\x97\xab?\xabZ\xef\xd4' \
    b'\x9e\xaa\xc6\xb3\xa4\xa3\x89\xb2\xd7b.\x8f\x16Ci_&\xe0\x7f', curve=SECP256K1)

    from cryptography.exceptions import InternalError
    with pytest.raises(InternalError):
        Point.from_bytes(point_on_koblitz256_but_not_P256.to_bytes(), curve=SECP256R1)


def test_serialize_point_at_infinity():

    p = Point.gen_rand()
    point_at_infinity = p - p
    
    bytes_point_at_infinity = point_at_infinity.to_bytes()
    assert bytes_point_at_infinity == b'\x00'


def test_coords_with_special_characteristics():

    # Testing that a point with x coordinate greater than the curve order is still valid.
    # In particular, we will test the last valid point from the default curve (secp256k1)
    # whose x coordinate is `field_order - 3` and is greater than the order of the curve

    field_order = 2**256 - 0x1000003D1
    compressed = b'\x02' + (field_order-3).to_bytes(32, 'big')

    last_point = Point.from_bytes(compressed)

    # The same point, but obtained through the from_affine method
    coords = (115792089237316195423570985008687907853269984665640564039457584007908834671660, 
        109188863561374057667848968960504138135859662956057034999983532397866404169138)

    assert last_point == Point.from_affine(coords)
