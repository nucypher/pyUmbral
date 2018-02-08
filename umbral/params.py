from cryptography.hazmat.primitives.asymmetric import ec


class UmbralParameters(object):
    def __init__(self, curve: ec.EllipticCurve):
        from umbral.point import Point
        from umbral.utils import unsafe_hash_to_point

        self.curve = curve

        self.g = Point.get_generator_from_curve(self.curve)
        self.order = Point.get_order_from_curve(self.curve)

        g_bytes = self.g.to_bytes(is_compressed=True)

        self.CURVE_MINVAL_SHA512 = (1 << 512) % int(self.order)
        self.CURVE_KEY_SIZE_BYTES = self.curve.key_size // 8

        domain_seed = b'NuCypherKMS/UmbralParameters/'
        self.h = unsafe_hash_to_point(self, g_bytes, domain_seed + b'h')
        self.u = unsafe_hash_to_point(self, g_bytes, domain_seed + b'u')
