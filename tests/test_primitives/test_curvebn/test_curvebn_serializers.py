import pytest

from umbral.curvebn import CurveBN
from umbral.curve import CURVES

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
