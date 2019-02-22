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

from cryptography.hazmat.backends.openssl import backend
from umbral.curvebn import CurveBN


def test_mocked_openssl_curvebn_arithmetic(mock_openssl, random_ec_curvebn1, random_ec_curvebn2):

    operations_that_construct = (
        random_ec_curvebn1 * random_ec_curvebn2,           # __mul__
        random_ec_curvebn1 ** random_ec_curvebn2,          # __pow__
        random_ec_curvebn1 ** int(random_ec_curvebn2),     # __pow__ (as int)
        random_ec_curvebn1 + random_ec_curvebn2,           # __add__
        random_ec_curvebn1 - random_ec_curvebn2,           # __sub__
        -random_ec_curvebn1,                               # __neg__
        random_ec_curvebn1 % random_ec_curvebn2,           # __mod__
        random_ec_curvebn1 % int(random_ec_curvebn2),      # __mod__ (as int)
        ~random_ec_curvebn1,                               # __invert__
        random_ec_curvebn1 / random_ec_curvebn2            # __truediv__
    )

    with mock_openssl():
        assert random_ec_curvebn1 == random_ec_curvebn1    # __eq__
        for operator_result in operations_that_construct:
            assert operator_result
            assert isinstance(operator_result, CurveBN)

    order = backend._bn_to_int(random_ec_curvebn1.curve.order)
    random_ec_curvebn1 = int(random_ec_curvebn1)
    random_ec_curvebn2 = int(random_ec_curvebn2)

    # For simplicity, we test these two cases separately 
    assert (int(operations_that_construct[-2]) * random_ec_curvebn1) % order == 1
    assert (int(operations_that_construct[-1]) * random_ec_curvebn2) % order == random_ec_curvebn1

    # The remaining cases can be tested in bulk
    expected_results = (
        (random_ec_curvebn1 * random_ec_curvebn2) % order,     # __mul__
        pow(random_ec_curvebn1, random_ec_curvebn2, order),    # __pow__
        pow(random_ec_curvebn1, random_ec_curvebn2, order),    # __pow__ (as int)
        (random_ec_curvebn1 + random_ec_curvebn2) % order,     # __add__
        (random_ec_curvebn1 - random_ec_curvebn2) % order,     # __sub__
        (-random_ec_curvebn1) % order,                         # __neg__
        random_ec_curvebn1 % random_ec_curvebn2,               # __mod__
        random_ec_curvebn1 % int(random_ec_curvebn2),          # __mod__ (as int)
    )

    for (result, expected) in zip(operations_that_construct[:-2], expected_results):
        assert result == expected
