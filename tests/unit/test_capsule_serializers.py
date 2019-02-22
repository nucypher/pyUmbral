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

from umbral.pre import Capsule
from umbral.curvebn import CurveBN
from umbral.point import Point


def test_capsule_serialization(capsule: Capsule):
    params = capsule.params
    capsule_bytes = capsule.to_bytes()
    capsule_bytes_casted = bytes(capsule)
    assert capsule_bytes == capsule_bytes_casted

    # A Capsule can be represented as the 98 total bytes of two Points (33 each) and a CurveBN (32).
    assert len(capsule_bytes) == Capsule.expected_bytes_length()

    new_capsule = Capsule.from_bytes(capsule_bytes, params)

    # Three ways to think about equality.
    # First, the public approach for the Capsule.  Simply:
    assert new_capsule == capsule

    # Second, we show that the original components (which is all we have here since we haven't activated) are the same:
    assert new_capsule.components() == capsule.components()

    # Third, we can directly compare the private original component attributes
    # (though this is not a supported approach):
    assert new_capsule.point_e == capsule.point_e
    assert new_capsule.point_v == capsule.point_v
    assert new_capsule.bn_sig == capsule.bn_sig


def test_cannot_create_capsule_from_bogus_material(alices_keys):
    params = alices_keys[0].params
    
    with pytest.raises(TypeError):
        _capsule_of_questionable_parentage = Capsule(params,
                                                     point_e=Point.gen_rand(),
                                                     point_v=42,
                                                     bn_sig=CurveBN.gen_rand())

    with pytest.raises(TypeError):
        _capsule_of_questionable_parentage = Capsule(params,
                                                     point_e=Point.gen_rand(),
                                                     point_v=Point.gen_rand(),
                                                     bn_sig=42)
