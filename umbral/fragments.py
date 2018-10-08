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

from umbral._pre import assess_cfrag_correctness, verify_kfrag
from umbral.config import default_curve, default_params
from umbral.curvebn import CurveBN
from umbral.keys import UmbralPublicKey
from umbral.point import Point
from umbral.signing import Signature
from umbral.params import UmbralParameters
from umbral.curve import Curve

from constant_sorrow.constants import NO_KEY, DELEGATING_ONLY, RECEIVING_ONLY, DELEGATING_AND_RECEIVING

NO_KEY(b'\x00')
DELEGATING_ONLY(b'\x01')
RECEIVING_ONLY(b'\x02')
DELEGATING_AND_RECEIVING(b'\x03')


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
        self._bn_key = bn_key
        self._point_commitment = point_commitment
        self._point_precursor = point_precursor
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
        # self._bn_key --> 1 bn_size
        # self._point_commitment --> 1 point_size
        # self._point_precursor --> 1 point_size
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
        key = self._bn_key.to_bytes()
        commitment = self._point_commitment.to_bytes()
        precursor = self._point_precursor.to_bytes()
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
        return verify_kfrag(kfrag=self,
                            params=params,
                            delegating_pubkey=delegating_pubkey,
                            signing_pubkey=signing_pubkey,
                            receiving_pubkey=receiving_pubkey)

    def verify_for_capsule(self, capsule: 'Capsule') -> bool:
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


class CorrectnessProof(object):
    def __init__(self, point_e2: Point, point_v2: Point, point_kfrag_commitment: Point,
                 point_kfrag_pok: Point, bn_sig: CurveBN, kfrag_signature: Signature,
                 metadata: Optional[bytes] = None) -> None:
        self._point_e2 = point_e2
        self._point_v2 = point_v2
        self._point_kfrag_commitment = point_kfrag_commitment
        self._point_kfrag_pok = point_kfrag_pok
        self.bn_sig = bn_sig
        self.metadata = metadata
        self.kfrag_signature = kfrag_signature

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None):
        """
        Returns the size (in bytes) of a CorrectnessProof without the metadata.
        If no curve is given, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve=curve)
        point_size = Point.expected_bytes_length(curve=curve)

        return (bn_size * 3) + (point_size * 4)

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'CorrectnessProof':
        """
        Instantiate CorrectnessProof from serialized data.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)
        arguments = {'curve': curve}
        splitter = BytestringSplitter(
            (Point, point_size, arguments),  # point_e2
            (Point, point_size, arguments),  # point_v2
            (Point, point_size, arguments),  # point_kfrag_commitment
            (Point, point_size, arguments),  # point_kfrag_pok
            (CurveBN, bn_size, arguments),  # bn_sig
            (Signature, Signature.expected_bytes_length(curve), arguments),  # kfrag_signature
        )
        components = splitter(data, return_remainder=True)
        components.append(components.pop() or None)

        return cls(*components)

    def to_bytes(self) -> bytes:
        """
        Serialize the CorrectnessProof to a bytestring.
        """
        e2 = self._point_e2.to_bytes()
        v2 = self._point_v2.to_bytes()
        kfrag_commitment = self._point_kfrag_commitment.to_bytes()
        kfrag_pok = self._point_kfrag_pok.to_bytes()

        result = e2 \
                 + v2 \
                 + kfrag_commitment \
                 + kfrag_pok \
                 + self.bn_sig.to_bytes() \
                 + self.kfrag_signature

        result += self.metadata or b''

        return result

    def __bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self,
                 point_e1: Point,
                 point_v1: Point,
                 kfrag_id: bytes,
                 point_precursor: Point,
                 proof: Optional[CorrectnessProof] = None) -> None:
        self._point_e1 = point_e1
        self._point_v1 = point_v1
        self._kfrag_id = kfrag_id
        self._point_precursor = point_precursor
        self.proof = proof

    class NoProofProvided(TypeError):
        """
        Raised when a cfrag is assessed for correctness, but no proof is attached.
        """

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        Returns the size (in bytes) of a CapsuleFrag given the curve without
        the CorrectnessProof.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        return (bn_size * 1) + (point_size * 3)

    @classmethod
    def from_bytes(cls, data: bytes, curve: Optional[Curve] = None) -> 'CapsuleFrag':
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)
        arguments = {'curve': curve}

        splitter = BytestringSplitter(
            (Point, point_size, arguments),  # point_e1
            (Point, point_size, arguments),  # point_v1
            bn_size,  # kfrag_id
            (Point, point_size, arguments),  # point_precursor
        )
        components = splitter(data, return_remainder=True)

        proof = components.pop() or None
        components.append(CorrectnessProof.from_bytes(proof, curve) if proof else None)

        return cls(*components)

    def to_bytes(self) -> bytes:
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self._point_e1.to_bytes()
        v1 = self._point_v1.to_bytes()
        precursor = self._point_precursor.to_bytes()

        serialized_cfrag = e1 + v1 + self._kfrag_id + precursor

        if self.proof is not None:
            serialized_cfrag += self.proof.to_bytes()

        return serialized_cfrag

    def verify_correctness(self, capsule: 'Capsule') -> bool:
        return assess_cfrag_correctness(self, capsule)

    def attach_proof(self,
                     e2: Point,
                     v2: Point,
                     u1: Point,
                     u2: Point,
                     z3: CurveBN,
                     kfrag_signature: Signature,
                     metadata: Optional[bytes]) -> None:

        self.proof = CorrectnessProof(point_e2=e2,
                                      point_v2=v2,
                                      point_kfrag_commitment=u1,
                                      point_kfrag_pok=u2,
                                      bn_sig=z3,
                                      kfrag_signature=kfrag_signature,
                                      metadata=metadata,
                                      )

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __repr__(self):
        return "CFrag:{}".format(self._point_e1.to_bytes().hex()[2:17])
