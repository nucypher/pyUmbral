import pytest
from umbral.curve import Curve, CURVES, SECP256R1, SECP256K1, SECP384R1


def test_curve_whitelist():
    # Test the AVAIL_CURVES dict to have only these three curves:
    assert len(CURVES) == 3
    assert Curve._supported_curves[415] == 'secp256r1'
    assert Curve._supported_curves[714] == 'secp256k1'
    assert Curve._supported_curves[715] == 'secp384r1'

    # Test that we can't instantiate other curves:
    with pytest.raises(NotImplementedError):
        Curve(711)

    # Test the hardcoded curves are what they're supposed to be:
    test_p256 = SECP256R1
    test_secp256k1 = SECP256K1
    test_p384 = SECP384R1

    assert test_p256.curve_nid == 415
    assert test_secp256k1.curve_nid == 714
    assert test_p384.curve_nid == 715

    # Test the supported curves property
    assert test_p256._supported_curves == Curve._supported_curves
    assert test_secp256k1._supported_curves == Curve._supported_curves
    assert test_p384._supported_curves == Curve._supported_curves
