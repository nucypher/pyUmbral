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

import hmac
from typing import Optional

from bytestring_splitter import BytestringSplitter

from umbral.config import default_curve, default_params
from umbral.curvebn import CurveBN
from umbral.keys import UmbralPublicKey
from umbral.point import Point
from umbral.signing import Signature
from umbral.params import UmbralParameters
from umbral.curve import Curve

NO_KEY = b'\x00'
DELEGATING_ONLY = b'\x01'
RECEIVING_ONLY = b'\x02'
DELEGATING_AND_RECEIVING = b'\x03'


class KFrag(object):

    def __init__(self,
                 identifier: bytes,
                 bn_key: CurveBN,
                 point_commitment: Point,
                 point_precursor: Point,
                 signature_for_proxy: Signature,
                 signature_for_bob: Signature,
                 keys_in_signature=DELEGATING_AND_RECEIVING,
                 ) -> None:
        self.id = identifier
        self.bn_key = bn_key
        self.point_commitment = point_commitment
        self.point_precursor = point_precursor
        self.signature_for_proxy = signature_for_proxy
        self.signature_for_bob = signature_for_bob
        self.keys_in_signature = keys_in_signature

    class NotValid(ValueError):
        """
        raised if the KFrag does not pass verification.
        """

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        Returns the size (in bytes) of a KFrag given the curve.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        # self.id --> 1 bn_size
        # self.bn_key --> 1 bn_size
        # self.point_commitment --> 1 point_size
        # self.point_precursor --> 1 point_size
        # self.signature_for_proxy --> 2 bn_size
        # self.signature_for_bob --> 2 bn_size
        # self.keys_in_signature --> 1

        return bn_size * 6 + point_size * 2 + 1

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'KFrag':
        """
        Instantiate a KFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)
        signature_size = Signature.expected_bytes_length(curve)
        arguments = {'curve': curve}

        splitter = BytestringSplitter(
            bn_size,  # id
            (CurveBN, bn_size, arguments),  # bn_key
            (Point, point_size, arguments),  # point_commitment
            (Point, point_size, arguments),  # point_precursor
            1,  # keys_in_signature
            (Signature, signature_size, arguments),  # signature_for_proxy
            (Signature, signature_size, arguments),  # signature_for_bob
        )
        components = splitter(data)

        return cls(identifier=components[0],
                   bn_key=components[1],
                   point_commitment=components[2],
                   point_precursor=components[3],
                   keys_in_signature=components[4],
                   signature_for_proxy=components[5],
                   signature_for_bob=components[6])

    def to_bytes(self) -> bytes:
        """
        Serialize the KFrag into a bytestring.
        """
        key = self.bn_key.to_bytes()
        commitment = self.point_commitment.to_bytes()
        precursor = self.point_precursor.to_bytes()
        signature_for_proxy = bytes(self.signature_for_proxy)
        signature_for_bob = bytes(self.signature_for_bob)
        mode = bytes(self.keys_in_signature)

        return self.id + key + commitment + precursor \
             + mode + signature_for_proxy + signature_for_bob

    def verify(self,
               signing_pubkey: UmbralPublicKey,
               delegating_pubkey: UmbralPublicKey = None,
               receiving_pubkey: UmbralPublicKey = None,
               params: Optional[UmbralParameters] = None,
               ) -> bool:
        if params is None:
            params = default_params()

        if delegating_pubkey and delegating_pubkey.params != params:
            raise ValueError("The delegating key uses different UmbralParameters")
        if receiving_pubkey and receiving_pubkey.params != params:
            raise ValueError("The receiving key uses different UmbralParameters")

        u = params.u

        kfrag_id = self.id
        key = self.bn_key
        commitment = self.point_commitment
        precursor = self.point_precursor

        #  We check that the commitment is well-formed
        correct_commitment = commitment == key * u
        validity_input = [kfrag_id, commitment, precursor, self.keys_in_signature]

        if self.delegating_key_in_signature():
            validity_input.append(delegating_pubkey)

        if self.receiving_key_in_signature():
            validity_input.append(receiving_pubkey)

        kfrag_validity_message = bytes().join(bytes(item) for item in validity_input)
        valid_kfrag_signature = self.signature_for_proxy.verify(kfrag_validity_message, signing_pubkey)

        return correct_commitment & valid_kfrag_signature

    def verify_for_capsule(self, capsule) -> bool:
        correctness_keys = capsule.get_correctness_keys()

        return self.verify(params=capsule.params,
                           signing_pubkey=correctness_keys["verifying"],
                           delegating_pubkey=correctness_keys["delegating"],
                           receiving_pubkey=correctness_keys["receiving"])

    def delegating_key_in_signature(self):
        return self.keys_in_signature == DELEGATING_ONLY or \
               self.keys_in_signature == DELEGATING_AND_RECEIVING

    def receiving_key_in_signature(self):
        return self.keys_in_signature == RECEIVING_ONLY or \
               self.keys_in_signature == DELEGATING_AND_RECEIVING

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __eq__(self, other):
        return hmac.compare_digest(bytes(self), bytes(other))

    def __hash__(self):
        return hash(bytes(self.id))

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, self.id.hex()[:15])
