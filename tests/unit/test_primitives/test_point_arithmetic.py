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
from umbral.point import Point


def test_mocked_openssl_point_arithmetic(mock_openssl, random_ec_point1, random_ec_point2, random_ec_curvebn1):

    operations_that_construct = (
        random_ec_point1 * random_ec_curvebn1, # __mul__
        random_ec_point1 + random_ec_point2,   # __add__
        random_ec_point1 - random_ec_point2,   # __sub__
        -random_ec_point1                      # __neg__
    )

    with mock_openssl():
        assert random_ec_point1 == random_ec_point1   # __eq__
        for operator_result in operations_that_construct:
            assert operator_result
            assert isinstance(operator_result, Point)


def test_point_curve_multiplication_regression():
    k256_point_bytes = b'\x03\xe0{\x1bQ\xbf@\x1f\x95\x8d\xe1\x17\xa7\xbe\x9e-G`T\xbf\xd7\x9e\xa7\x10\xc8uA\xc0z$\xc0\x92\x8a'
    k256_bn_bytes = b'4u\xd70-\xa0h\xdeG\xf0\x143\x06!\x91\x05{\xe4jC\n\xf1h\xed7a\xf8\x9d\xec^\x19\x8c'

    k256_point = Point.from_bytes(k256_point_bytes)
    k256_bn = CurveBN.from_bytes(k256_bn_bytes)

    product_with_star_operator = k256_point * k256_bn

    # Make sure we have instantiated a new, unequal point in the same curve and group
    assert isinstance(product_with_star_operator, Point), "Point.__mul__ did not return a point instance"
    assert k256_point != product_with_star_operator
    assert k256_point.curve == product_with_star_operator.curve

    product_bytes = b'\x03\xc9\xda\xa2\x88\xe2\xa0+\xb1N\xb6\xe6\x1c\xa5(\xe6\xe0p\xf6\xf4\xa9\xfc\xb1\xfaUV\xd3\xb3\x0e4\x94\xbe\x12'
    product_point = Point.from_bytes(product_bytes)
    assert product_with_star_operator.to_bytes() == product_bytes
    assert product_point == product_with_star_operator

    # Repeating the operation, should return the same result.
    product_with_star_operator_again = k256_point * k256_bn
    assert product_with_star_operator == product_with_star_operator_again
