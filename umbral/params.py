from cryptography.hazmat.primitives.asymmetric import ec


class UmbralParameters(object):
    def __init__(self, curve: ec.EllipticCurve):
        from umbral.point import Point
        from umbral.utils import unsafe_hash_to_point

        self.curve = curve

        self.g = Point.get_generator_from_curve(self.curve)
        self.order = Point.get_order_from_curve(self.curve)

        g_bytes = self.g.to_bytes(is_compressed=True)

        domain_seed = b'NuCypherKMS/UmbralParameters/'

        self.h = unsafe_hash_to_point(self.curve, g_bytes, domain_seed + b'h')
        self.u = unsafe_hash_to_point(self.curve, g_bytes, domain_seed + b'u')

        CURVE_MINVAL_SHA512 = (1 << 512) % self.order
