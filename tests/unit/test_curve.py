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

from umbral.curve import Curve


def test_supported_curves():

    # Ensure we have the correct number opf supported curves hardcoded
    number_of_supported_curves = 3
    assert len(Curve._supported_curves) == number_of_supported_curves

    # Manually ensure the `_supported curves` dict contains only valid supported curves
    assert Curve._supported_curves[415] == 'secp256r1'
    assert Curve._supported_curves[714] == 'secp256k1'
    assert Curve._supported_curves[715] == 'secp384r1'

    nid, name = 714, 'secp256k1'

    #
    # Create by NID
    #

    # supported
    _curve_714 = Curve(nid=nid)
    assert _curve_714.curve_nid == nid
    assert _curve_714.name == name

    # unsuported
    with pytest.raises(NotImplementedError):
        _ = Curve(711)


    #
    # Create by Name
    #

    # Supported
    _curve_secp256k1 = Curve.from_name(name)
    assert _curve_secp256k1.name == name
    assert _curve_secp256k1.curve_nid == nid

    # Unsupported
    with pytest.raises(NotImplementedError):
        _ = Curve.from_name('abcd123e4')

    # Import curve constants
    from umbral.curve import SECP256R1, SECP256K1, SECP384R1
    test_p256 = SECP256R1
    test_secp256k1 = SECP256K1
    test_p384 = SECP384R1

    # Test the hardcoded curve NIDs are correct:
    assert test_p256.curve_nid == 415
    assert test_secp256k1.curve_nid == 714
    assert test_p384.curve_nid == 715

    # Ensure every curve constant is in the CURVES collection
    from umbral.curve import CURVES
    assert len(CURVES) == number_of_supported_curves

    # Ensure all supported curves can be initialized
    for nid, name in Curve._supported_curves.items():
        _curve_nid, _curve_name = Curve(nid=nid), Curve.from_name(name)
        assert _curve_nid.name == name
        assert _curve_name.curve_nid == nid
