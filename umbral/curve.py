from cryptography.hazmat.backends import default_backend
from umbral import openssl

_AVAIL_CURVES = {
    'secp256r1': 415,
    'secp256k1': 714,
    'secp384r1': 715,
}


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    curve_nid, the EC_GROUP struct, and the order of the curve. This also acts
    as a convenient whitelist to limit the curves used in pyUmbral.
    """

    def __init__(self, curve_nid: int):
        """
        Instantiates an OpenSSL curve with the provided curve_nid and derives
        the proper EC_GROUP struct and order. You can _only_ instantiate curves
        with supported nids (see `Curve.supported_curves`).
        """
        if curve_nid not in _AVAIL_CURVES.values():
            raise ValueError(
                "Curve NID passed ({}) is not supported.".format(curve_nid))

        self.curve_nid = curve_nid
        self.ec_group = openssl._get_ec_group_by_curve_nid(self.curve_nid)
        self.order = openssl._get_ec_order_by_group(self.ec_group)
        self.generator = openssl._get_ec_generator_by_group(self.ec_group)

    @property
    def supported_curves(self):
        return _AVAIL_CURVES

    def __eq__(self, other):
        return self.curve_nid == other.curve_nid

    def __repr__(self):
        return "<OpenSSL Curve w/ NID {}>".format(self.curve_nid)

    def get_field_order_size_in_bytes(self) -> int:
        backend = default_backend()
        size_in_bits = openssl._get_ec_group_degree(self.ec_group)
        return (size_in_bits + 7) // 8



SECP256R1 = Curve(_AVAIL_CURVES['secp256r1'])
SECP256K1 = Curve(_AVAIL_CURVES['secp256k1'])
SECP384R1 = Curve(_AVAIL_CURVES['secp384r1'])
