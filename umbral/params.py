"""
Copyright (C) 2018 NuCypher

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

from umbral.curve import Curve


class UmbralParameters(object):
    def __init__(self, curve: Curve) -> None:
        from umbral.point import Point, unsafe_hash_to_point

        self.curve = curve
        self.CURVE_KEY_SIZE_BYTES = self.curve.field_order_size_in_bytes

        self.g = Point.get_generator_from_curve(curve=curve)
        g_bytes = self.g.to_bytes()

        parameters_seed = b'NuCypher/UmbralParameters/'
        self.u = unsafe_hash_to_point(g_bytes, self, parameters_seed + b'u')

    def __eq__(self, other) -> bool:

        # TODO: This is not comparing the order, which currently is an OpenSSL pointer
        self_attributes = self.curve, self.g, self.CURVE_KEY_SIZE_BYTES, self.u
        others_attributes = other.curve, other.g, other.CURVE_KEY_SIZE_BYTES, other.u

        return self_attributes == others_attributes
