from cryptography.hazmat.backends import default_backend

from umbral import openssl


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    __curve_nid, the EC_GROUP struct, and the order of the curve.

    Contains a whitelist of supported elliptic curves used in pyUmbral.

    """

    _supported_curves = {
        415: 'secp256r1',
        714: 'secp256k1',
        715: 'secp384r1'
    }

    def __init__(self, nid: int) -> None:
        """
        Instantiates an OpenSSL curve with the provided __curve_nid and derives
        the proper EC_GROUP struct and order. You can _only_ instantiate curves
        with supported nids (see `Curve.supported_curves`).
        """

        try:
            self.__curve_name = self._supported_curves[nid]
        except KeyError:
            raise NotImplementedError("Curve NID {} is not supported.".format(nid))

        # set only once
        self.__curve_nid = nid
        self.__ec_group = openssl._get_ec_group_by_curve_nid(self.__curve_nid)
        self.__order = openssl._get_ec_order_by_group(self.ec_group)
        self.__generator = openssl._get_ec_generator_by_group(self.ec_group)

    @property
    def curve_nid(self):
        return self.__curve_nid

    @property
    def ec_group(self):
        return self.__ec_group

    @property
    def order(self):
        return self.__order

    @property
    def generator(self):
        return self.__generator

    @classmethod
    def from_name(cls, name: str):
        return cls(nid=cls._supported_curves[name])

    def __eq__(self, other):
        return self.__curve_nid == other.curve_nid

    def __repr__(self):
        return "<OpenSSL Curve(nid={})>".format(self.__curve_nid)

    def get_field_order_size_in_bytes(self) -> int:
        backend = default_backend()
        size_in_bits = openssl._get_ec_group_degree(self.ec_group)
        return (size_in_bits + 7) // 8


SECP256R1 = Curve.from_name('secp256r1')
SECP256K1 = Curve.from_name('secp256k1')
SECP384R1 = Curve.from_name('secp384r1')
CURVES = (SECP256K1, SECP256R1, SECP384R1)
