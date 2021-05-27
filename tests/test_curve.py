import pytest

from umbral.openssl import Curve, bn_to_int, point_to_affine_coords
from umbral.curve import CURVE, SECP256K1


def test_supported_curves():

    # Ensure we have the correct number of supported curves hardcoded
    number_of_supported_curves = 1
    assert len(Curve._supported_curves) == number_of_supported_curves

    # Manually ensure the `_supported curves` dict contains only valid supported curves
    assert Curve._supported_curves[714] == 'secp256k1'


def test_create_by_nid():

    nid, name = 714, 'secp256k1'

    # supported
    _curve_714 = Curve(nid=nid)
    assert _curve_714.nid == nid
    assert _curve_714.name == name

    # unsuported
    with pytest.raises(NotImplementedError):
        Curve(711)


def test_create_by_name():

    nid, name = 714, 'secp256k1'

    # Supported
    _curve_secp256k1 = Curve.from_name(name)
    assert _curve_secp256k1.name == name
    assert _curve_secp256k1.nid == nid

    # Unsupported
    with pytest.raises(NotImplementedError):
        Curve.from_name('abcd123e4')


def test_curve_constants():

    test_secp256k1 = SECP256K1

    assert CURVE == SECP256K1

    # Test the hardcoded curve NIDs are correct:
    assert test_secp256k1.nid == 714

    # Ensure all supported curves can be initialized
    for nid, name in Curve._supported_curves.items():
        by_nid, by_name = Curve(nid=nid), Curve.from_name(name)
        assert by_nid.name == name
        assert by_name.nid == nid


def test_curve_str():
    for nid in Curve._supported_curves:
        curve = Curve(nid=nid)
        s = str(curve)
        assert str(curve.nid) in s
        assert str(curve.name) in s


def _curve_info(curve: Curve):
    assert bn_to_int(curve.bn_order) == curve.order
    return dict(order=curve.order,
                field_element_size=curve.field_element_size,
                scalar_size=curve.scalar_size,
                generator=point_to_affine_coords(curve, curve.point_generator))


def test_secp256k1():
    info = _curve_info(SECP256K1)
    assert info['order'] == 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
    assert info['field_element_size'] == 32
    assert info['scalar_size'] == 32
    assert info['generator'] == (
        0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798,
        0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8)
