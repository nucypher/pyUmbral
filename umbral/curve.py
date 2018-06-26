from umbral import openssl


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    curve_nid, the EC_GROUP struct, and the order of the curve. This also acts
    as a convenient whitelist to limit the curves used in pyUmbral.
    """

    AVAIL_CURVES = {
        'secp256r1': 415,
        'secp256k1': 714,
        'secp384r1': 715,
    }

    def __init__(self, curve_nid: int):
        if curve_nid not in self.AVAIL_CURVES.values():
            raise ValueError(
                "Curve NID passed ({}) is not supported.".format(curve_nid))

        # TODO: Limit the creations of EC_GROUP structs in openssl.py
        self.curve_nid = curve_nid
        self.ec_group = openssl._get_ec_group_by_curve_nid(self.curve_nid)
        self.order = openssl._get_ec_order_by_curve_nid(self.curve_nid)


class SECP256R1(Curve):
    """
    Instantiates a NIST secp256r1 (P-256) curve.
    """
    def __init__(self):
        super().__init__(super().AVAIL_CURVES['secp256r1'])


class SECP256K1(Curve):
    """
    Instantiates a SECG secp256k1 curve.
    This is the default curve currently used in NuCypher.
    """
    def __init__(self):
        super().__init__(super().AVAIL_CURVES['secp256k1'])


class SECP384R1(Curve):
    """
    Instantiates a NIST secp384r1 (P-384) curve.
    """
    def __init__(self):
        super().__init__(super().AVAIL_CURVES['secp384r1'])
