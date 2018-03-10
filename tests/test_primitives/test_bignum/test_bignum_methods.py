from umbral.bignum import BigNum


def test_cast_bignum_to_int():
    x = BigNum.gen_rand()

    x_as_int_from_dunder = x.__int__()
    x_as_int_type_caster = int(x)
    assert x_as_int_from_dunder == x_as_int_type_caster
    x = x_as_int_type_caster

    y = BigNum.from_int(x)
    assert x == y
