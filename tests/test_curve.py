import pytest

from umbral.openssl import Curve, bn_to_int, point_to_affine_coords
from umbral.curve import CURVE, CURVES, SECP256R1, SECP256K1, SECP384R1


def test_supported_curves():

    # Ensure we have the correct number of supported curves hardcoded
    number_of_supported_curves = 3
    assert len(Curve._supported_curves) == number_of_supported_curves

    # Manually ensure the `_supported curves` dict contains only valid supported curves
    assert Curve._supported_curves[415] == 'secp256r1'
    assert Curve._supported_curves[714] == 'secp256k1'
    assert Curve._supported_curves[715] == 'secp384r1'


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

    test_p256 = SECP256R1
    test_secp256k1 = SECP256K1
    test_p384 = SECP384R1

    assert CURVE == SECP256K1

    # Test the hardcoded curve NIDs are correct:
    assert test_p256.nid == 415
    assert test_secp256k1.nid == 714
    assert test_p384.nid == 715

    # Ensure every curve constant is in the CURVES collection
    number_of_supported_curves = 3
    assert len(CURVES) == number_of_supported_curves

    # Ensure all supported curves can be initialized
    for nid, name in Curve._supported_curves.items():
        by_nid, by_name = Curve(nid=nid), Curve.from_name(name)
        assert by_nid.name == name
        assert by_name.nid == nid


def test_curve_str():
    for curve in CURVES:
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


def test_p256():
    info = _curve_info(SECP256R1)
    assert info['order'] == 0xFFFFFFFF_00000000_FFFFFFFF_FFFFFFFF_BCE6FAAD_A7179E84_F3B9CAC2_FC632551
    assert info['field_element_size'] == 32
    assert info['scalar_size'] == 32
    assert info['generator'] == (
        0x6B17D1F2_E12C4247_F8BCE6E5_63A440F2_77037D81_2DEB33A0_F4A13945_D898C296,
        0x4FE342E2_FE1A7F9B_8EE7EB4A_7C0F9E16_2BCE3357_6B315ECE_CBB64068_37BF51F5)


def test_p384():
    info = _curve_info(SECP384R1)
    assert info['order'] == 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_C7634D81_F4372DDF_581A0DB2_48B0A77A_ECEC196A_CCC52973
    assert info['field_element_size'] == 48
    assert info['scalar_size'] == 48
    assert info['generator'] == (
         0xAA87CA22_BE8B0537_8EB1C71E_F320AD74_6E1D3B62_8BA79B98_59F741E0_82542A38_5502F25D_BF55296C_3A545E38_72760AB7,
         0x3617DE4A_96262C6F_5D9E98BF_9292DC29_F8F41DBD_289A147C_E9DA3113_B5F0B8C0_0A60B1CE_1D7E819D_7A431D7C_90EA0E5F)
