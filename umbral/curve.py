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

from cryptography.hazmat.backends import default_backend

from umbral import openssl


class Curve:
    """
    Acts as a container to store constant variables such as the OpenSSL
    curve_nid, the EC_GROUP struct, and the order of the curve.

    Contains a whitelist of supported elliptic curves used in pyUmbral.

    """

    _supported_curves = {
        415: 'secp256r1',
        714: 'secp256k1',
        715: 'secp384r1'
    }

    def __init__(self, nid: int) -> None:
        """
        Instantiates an OpenSSL curve with the provided curve_nid and derives
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

        # Init cache
        self.__field_order_size_in_bytes = 0
        self.__group_order_size_in_bytes = 0

    @classmethod
    def from_name(cls, name: str) -> 'Curve':
        """
        Alternate constructor to generate a curve instance by its name.

        Raises NotImplementedError if the name cannot be mapped to a known
        supported curve NID.

        """

        name = name.casefold()  # normalize

        for supported_nid, supported_name in cls._supported_curves.items():
            if name == supported_name:
                instance = cls(nid=supported_nid)
                break
        else:
            message = "{} is not supported curve name.".format(name)
            raise NotImplementedError(message)

        return instance

    def __eq__(self, other):
        return self.__curve_nid == other.curve_nid

    def __repr__(self):
        return "<OpenSSL Curve(nid={}, name={})>".format(self.__curve_nid, self.__curve_name)

    #
    # Immutable Curve Data
    #

    @property
    def field_order_size_in_bytes(self) -> int:
        if not self.__field_order_size_in_bytes:
            size_in_bits = openssl._get_ec_group_degree(self.__ec_group)
            self.__field_order_size_in_bytes = (size_in_bits + 7) // 8
        return self.__field_order_size_in_bytes

    @property
    def group_order_size_in_bytes(self) -> int:
        if not self.__group_order_size_in_bytes:
            BN_num_bytes = default_backend()._lib.BN_num_bytes
            self.__group_order_size_in_bytes = BN_num_bytes(self.order)
        return self.__group_order_size_in_bytes

    @property
    def curve_nid(self) -> int:
        return self.__curve_nid

    @property
    def name(self) -> str:
        return self.__curve_name

    @property
    def ec_group(self):
        return self.__ec_group

    @property
    def order(self):
        return self.__order

    @property
    def generator(self):
        return self.__generator


#
# Global Curve Instances
#

SECP256R1 = Curve.from_name('secp256r1')
SECP256K1 = Curve.from_name('secp256k1')
SECP384R1 = Curve.from_name('secp384r1')

CURVES = (SECP256K1, SECP256R1, SECP384R1)
