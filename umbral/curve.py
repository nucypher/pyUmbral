from umbral import openssl


CURVE_WHITELIST = {
    'secp256r1': 415,
    'secp256k1': 714,
    'secp384r1': 715,
}


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    curve_nid, the EC_GROUP struct, and the order of the curve. This also acts
    as a convenient interface to limit the curves used in pyUmbral.
    """
    def __init__(self, curve_nid: int):
        # TODO: Limit the creations of EC_GROUP structs in openssl.py
        self.curve_nid = curve_nid
        self.ec_group = openssl._get_ec_group_by_curve_nid(self.curve_nid)
        self.order = openssl._get_ec_order_by_curve_nid(self.curve_nid)
