import pytest
from umbral.curve import Curve, SECP256R1, SECP256K1, SECP384R1, _AVAIL_CURVES


def test_curve_whitelist():
    # Test the AVAIL_CURVES dict to have only these three curves:
    assert len(_AVAIL_CURVES) == 3
    assert _AVAIL_CURVES['secp256r1'] == 415
    assert _AVAIL_CURVES['secp256k1'] == 714
    assert _AVAIL_CURVES['secp384r1'] == 715

    # Test that we can't instantiate other curves:
    with pytest.raises(ValueError):
        Curve(711)

    # Test the hardcoded curves are what they're supposed to be:
    test_p256 = SECP256R1
    test_secp256k1 = SECP256K1
    test_p384 = SECP384R1

    assert test_p256.curve_nid == 415
    assert test_secp256k1.curve_nid == 714
    assert test_p384.curve_nid == 715

    # Test the supported curves property
    assert test_p256.supported_curves == _AVAIL_CURVES
    assert test_secp256k1.supported_curves == _AVAIL_CURVES
    assert test_p384.supported_curves == _AVAIL_CURVES

