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

from typing import Optional, Any

from bytestring_splitter import BytestringSplitter

from umbral.config import default_curve
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.signing import Signature
from umbral.curve import Curve
from umbral.random_oracles import hash_to_curvebn, ExtendedKeccak


class CorrectnessProof(object):
    def __init__(self, point_e2: Point, point_v2: Point, point_kfrag_commitment: Point,
                 point_kfrag_pok: Point, bn_sig: CurveBN, kfrag_signature: Signature,
                 metadata: Optional[bytes] = None) -> None:
        self.point_e2 = point_e2
        self.point_v2 = point_v2
        self.point_kfrag_commitment = point_kfrag_commitment
        self.point_kfrag_pok = point_kfrag_pok
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
        e2 = self.point_e2.to_bytes()
        v2 = self.point_v2.to_bytes()
        kfrag_commitment = self.point_kfrag_commitment.to_bytes()
        kfrag_pok = self.point_kfrag_pok.to_bytes()

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
        self.point_e1 = point_e1
        self.point_v1 = point_v1
        self.kfrag_id = kfrag_id
        self.point_precursor = point_precursor
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
        e1 = self.point_e1.to_bytes()
        v1 = self.point_v1.to_bytes()
        precursor = self.point_precursor.to_bytes()

        serialized_cfrag = e1 + v1 + self.kfrag_id + precursor

        if self.proof is not None:
            serialized_cfrag += self.proof.to_bytes()

        return serialized_cfrag

    def prove_correctness(self,
                          capsule,
                          kfrag,
                          metadata: Optional[bytes] = None):

        params = capsule.params

        # Check correctness of original ciphertext
        if not capsule.verify():
            raise capsule.NotValid("Capsule verification failed.")

        rk = kfrag.bn_key
        t = CurveBN.gen_rand(params.curve)
        ####
        # Here are the formulaic constituents shared with `verify_correctness`.
        ####
        e = capsule.point_e
        v = capsule.point_v

        e1 = self.point_e1
        v1 = self.point_v1

        u = params.u
        u1 = kfrag.point_commitment

        e2 = t * e  # type: Any
        v2 = t * v  # type: Any
        u2 = t * u  # type: Any

        hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
        if metadata is not None:
            hash_input.append(metadata)

        h = hash_to_curvebn(*hash_input, params=params, hash_class=ExtendedKeccak)
        ########

        z3 = t + h * rk

        self.attach_proof(e2, v2, u1, u2, metadata=metadata, z3=z3, kfrag_signature=kfrag.signature_for_bob)

    def verify_correctness(self, capsule) -> bool:
        if self.proof is None:
            raise CapsuleFrag.NoProofProvided

        correctness_keys = capsule.get_correctness_keys()

        delegating_pubkey = correctness_keys['delegating']
        signing_pubkey = correctness_keys['verifying']
        receiving_pubkey = correctness_keys['receiving']

        params = capsule.params

        ####
        # Here are the formulaic constituents shared with `prove_correctness`.
        ####
        e = capsule.point_e
        v = capsule.point_v

        e1 = self.point_e1
        v1 = self.point_v1

        u = params.u
        u1 = self.proof.point_kfrag_commitment

        e2 = self.proof.point_e2
        v2 = self.proof.point_v2
        u2 = self.proof.point_kfrag_pok

        hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
        if self.proof.metadata is not None:
            hash_input.append(self.proof.metadata)

        h = hash_to_curvebn(*hash_input, params=params, hash_class=ExtendedKeccak)
        ########

        precursor = self.point_precursor
        kfrag_id = self.kfrag_id

        validity_input = (kfrag_id, delegating_pubkey, receiving_pubkey, u1, precursor)

        kfrag_validity_message = bytes().join(bytes(item) for item in validity_input)
        valid_kfrag_signature = self.proof.kfrag_signature.verify(kfrag_validity_message, signing_pubkey)

        z3 = self.proof.bn_sig
        correct_reencryption_of_e = z3 * e == e2 + (h * e1)

        correct_reencryption_of_v = z3 * v == v2 + (h * v1)

        correct_rk_commitment = z3 * u == u2 + (h * u1)

        return valid_kfrag_signature \
               & correct_reencryption_of_e \
               & correct_reencryption_of_v \
               & correct_rk_commitment

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
        return "CFrag:{}".format(self.point_e1.to_bytes().hex()[2:17])
