from cryptography.hazmat.backends.openssl import backend

from umbral import openssl
from umbral.curve import Curve


class UmbralParameters(object):
    def __init__(self, curve: Curve) -> None:
        from umbral.point import Point, unsafe_hash_to_point

        self.curve = curve
        self.CURVE_KEY_SIZE_BYTES = self.curve.get_field_order_size_in_bytes

        self.g = Point.get_generator_from_curve(curve=curve)
        g_bytes = self.g.to_bytes()

        parameters_seed = b'NuCypher/UmbralParameters/'
        self.u = unsafe_hash_to_point(g_bytes, self, parameters_seed + b'u')

    def __eq__(self, other: 'UmbralParameters') -> bool:

        self_curve_nid = self.curve.curve_nid
        other_curve_nid = other.curve.curve_nid

        # TODO: This is not comparing the order, which currently is an OpenSSL pointer
        self_attributes = self_curve_nid, self.g, self.CURVE_KEY_SIZE_BYTES, self.u
        others_attributes = other_curve_nid, other.g, other.CURVE_KEY_SIZE_BYTES, other.u

        return self_attributes == others_attributes
