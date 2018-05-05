from umbral.curvebn import CurveBN
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
        CurveBN.hash(whatever)
