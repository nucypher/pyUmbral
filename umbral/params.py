from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend
from umbral import _openssl


class UmbralParameters(object):
    def __init__(self, curve: ec.EllipticCurve):
        from umbral.point import Point, unsafe_hash_to_point
        from umbral.utils import get_curve_keysize_bytes

        self.curve = curve
        curve_nid = backend._elliptic_curve_to_nid(curve)

        self.g = Point.get_generator_from_curve(self.curve)
        
        self.order = _openssl._get_ec_order_by_curve_nid(curve_nid)

        g_bytes = self.g.to_bytes(is_compressed=True)

        self.CURVE_KEY_SIZE_BYTES = get_curve_keysize_bytes(self.curve)

        parameters_seed = b'NuCypherKMS/UmbralParameters/'
        self.u = unsafe_hash_to_point(g_bytes, self, parameters_seed + b'u')
