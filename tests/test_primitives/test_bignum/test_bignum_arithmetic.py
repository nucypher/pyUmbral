from umbral.curvebn import CurveBN


def test_mocked_openssl_curvebn_arithmetic(mock_openssl, random_ec_curvebn1, random_ec_curvebn2):

    operations_that_construct = (
        random_ec_curvebn1 * random_ec_curvebn2,           # __mul__
        random_ec_curvebn1 ** random_ec_curvebn2,          # __pow__
        random_ec_curvebn1 ** int(random_ec_curvebn2),     # __pow__ (as int)
        random_ec_curvebn1 + random_ec_curvebn2,           # __add__
        random_ec_curvebn1 - random_ec_curvebn2,           # __sub__
        random_ec_curvebn1 % random_ec_curvebn2,           # __mod__
        random_ec_curvebn1 % int(random_ec_curvebn2),      # __mod__ (as int)
        ~random_ec_curvebn1,                              # __invert__
        random_ec_curvebn1 / random_ec_curvebn2            # __truediv__
    )

    with mock_openssl():
        assert random_ec_curvebn1 == random_ec_curvebn1    # __eq__
        for operator_result in operations_that_construct:
            assert operator_result
            assert isinstance(operator_result, CurveBN)

