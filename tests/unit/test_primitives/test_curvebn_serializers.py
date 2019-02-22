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

from umbral.curvebn import CurveBN
from umbral.curve import CURVES
from cryptography.hazmat.backends import default_backend

@pytest.mark.parametrize("curve", CURVES)
def test_serialization_rotations_of_1(curve):

    size_in_bytes = CurveBN.expected_bytes_length(curve)
    for i in range(size_in_bytes):
        lonely_one = 1 << i
        bn = CurveBN.from_int(lonely_one, curve)
        lonely_one_in_bytes = lonely_one.to_bytes(size_in_bytes, 'big')

        # Check serialization
        assert bn.to_bytes() == lonely_one_in_bytes

        # Check deserialization
        assert CurveBN.from_bytes(lonely_one_in_bytes, curve) == bn

@pytest.mark.parametrize("curve", CURVES)
def test_invalid_deserialization(curve):
	size_in_bytes = CurveBN.expected_bytes_length(curve)
	
	# All-zeros bytestring are invalid (i.e., 0 < bn < order of the curve)
	zero_bytes = bytes(size_in_bytes)
	with pytest.raises(ValueError):
		_bn = CurveBN.from_bytes(zero_bytes, curve)

	# All-ones bytestring is invalid too (since it's greater than order)
	lots_of_ones = 2**(8*size_in_bytes) - 1
	lots_of_ones = lots_of_ones.to_bytes(size_in_bytes, 'big')
	with pytest.raises(ValueError):
		_bn = CurveBN.from_bytes(lots_of_ones, curve)

	# Serialization of `order` is invalid since it's not strictly lower than 
	# the order of the curve
	order = default_backend()._bn_to_int(curve.order)
	with pytest.raises(ValueError):
		_bn = CurveBN.from_bytes(order.to_bytes(size_in_bytes, 'big'), curve)

	# On the other hand, serialization of `order - 1` is valid
	order -= 1
	_bn = CurveBN.from_bytes(order.to_bytes(size_in_bytes, 'big'), curve)
