import pytest

from umbral.curvebn import CurveBN

def test_serialize_rotations_of_1():
    
    for i in range(32):

        lonely_one = 1 << i
        bn = CurveBN.from_int(lonely_one)
        assert bn.to_bytes() == lonely_one.to_bytes(32, 'big')


        


