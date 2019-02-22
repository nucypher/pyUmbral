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

from umbral.curvebn import CurveBN
from umbral.random_oracles import hash_to_curvebn
import pytest


def test_cast_curvebn_to_int():
    x = CurveBN.gen_rand()

    x_as_int_from_dunder = x.__int__()
    x_as_int_type_caster = int(x)
    assert x_as_int_from_dunder == x_as_int_type_caster
    x = x_as_int_type_caster

    y = CurveBN.from_int(x)
    assert x == y


def test_cant_hash_arbitrary_object_into_bignum():
    whatever = object()
    with pytest.raises(TypeError):
        hash_to_curvebn(whatever)

