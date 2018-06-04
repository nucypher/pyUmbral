from bytestring_splitter import BytestringSplitter
from cryptography.hazmat.primitives.asymmetric import ec

from umbral._pre import assess_cfrag_correctness, verify_kfrag
from umbral.config import default_curve, default_params
from umbral.curvebn import CurveBN
from umbral.keys import UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point

from umbral.signing import Signature


class KFrag(object):
    def __init__(self, id, bn_key, point_noninteractive,
                 point_commitment, point_xcoord, signature):
        self._id = id
        self._bn_key = bn_key
        self._point_noninteractive = point_noninteractive
        self._point_commitment = point_commitment
        self._point_xcoord = point_xcoord
        self.signature = signature

    @classmethod
    def expected_bytes_length(cls, curve: ec.EllipticCurve = None):
        """
        Returns the size (in bytes) of a KFrag given the curve.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        return (bn_size * 4) + (point_size * 3)

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiate a KFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        splitter = BytestringSplitter(
            bn_size,             # id
            (CurveBN, bn_size),  # bn_key
            (Point, point_size), # point_noninteractive
            (Point, point_size), # point_commitment
            (Point, point_size), # point_xcoord
            (Signature, Signature.expected_bytes_length(curve))
        )
        components = splitter(data)

        return cls(*components)

    def to_bytes(self):
        """
        Serialize the KFrag into a bytestring.
        """
        key = self._bn_key.to_bytes()
        ni = self._point_noninteractive.to_bytes()
        commitment = self._point_commitment.to_bytes()
        xcoord = self._point_xcoord.to_bytes()
        signature = bytes(self.signature)

        return self._id + key + ni + commitment + xcoord + signature

    def verify(self,
               signing_pubkey,
               delegating_pubkey: UmbralPublicKey,
               receiving_pubkey: UmbralPublicKey):

        params = delegating_pubkey.params

        return verify_kfrag(self,
                            delegating_pubkey.point_key,
                            signing_pubkey,
                            receiving_pubkey.point_key,
                            params)

    def __bytes__(self):
        return self.to_bytes()


class CorrectnessProof(object):
    def __init__(self, point_e2, point_v2, point_kfrag_commitment,
                 point_kfrag_pok, bn_sig, kfrag_signature: bytes, metadata: bytes = None):
        self._point_e2 = point_e2
        self._point_v2 = point_v2
        self._point_kfrag_commitment = point_kfrag_commitment
        self._point_kfrag_pok = point_kfrag_pok
        self.bn_sig = bn_sig
        self.metadata = metadata
        self.kfrag_signature = kfrag_signature

    @classmethod
    def expected_bytes_length(cls, curve: ec.EllipticCurve = None):
        """
        Returns the size (in bytes) of a CorrectnessProof without the metadata.
        If no curve is given, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve=curve)
        point_size = Point.expected_bytes_length(curve=curve)

        return (bn_size * 3) + (point_size * 4)

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiate CorrectnessProof from serialized data.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        splitter = BytestringSplitter(
            (Point, point_size), # point_e2
            (Point, point_size), # point_v2
            (Point, point_size), # point_kfrag_commitment
            (Point, point_size), # point_kfrag_pok
            (CurveBN, bn_size),  # bn_sig
            (Signature), # kfrag_signature
        )
        components = splitter(data, return_remainder=True)
        metadata = components.pop(-1) or None

        return cls(*components, metadata=metadata)

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

    def _bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self, point_e1, point_v1, kfrag_id, point_noninteractive,
                 point_xcoord, proof: CorrectnessProof = None):
        self._point_e1 = point_e1
        self._point_v1 = point_v1
        self._kfrag_id = kfrag_id
        self._point_noninteractive = point_noninteractive
        self._point_xcoord = point_xcoord
        self.proof = proof

    class NoProofProvided(TypeError):
        """
        Raised when a cfrag is assessed for correctness, but no proof is attached.
        """

    @classmethod
    def expected_bytes_length(cls, curve: ec.EllipticCurve = None):
        """
        Returns the size (in bytes) of a CapsuleFrag given the curve without
        the CorrectnessProof.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        return (bn_size * 1) + (point_size * 4)

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        splitter = BytestringSplitter(
            (Point, point_size), # point_e1
            (Point, point_size), # point_v1
            bn_size,             # kfrag_id
            (Point, point_size), # point_noninteractive
            (Point, point_size)  # point_xcoord
        )
        components = splitter(data, return_remainder=True)

        proof = components.pop(-1) or None
        proof = CorrectnessProof.from_bytes(proof, curve) if proof else None
        return cls(*components, proof)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self._point_e1.to_bytes()
        v1 = self._point_v1.to_bytes()
        ni = self._point_noninteractive.to_bytes()
        xcoord = self._point_xcoord.to_bytes()

        serialized_cfrag = e1 + v1 + self._kfrag_id + ni + xcoord

        if self.proof is not None:
            serialized_cfrag += self.proof.to_bytes()

        return serialized_cfrag

    def verify_correctness(self, capsule: "Capsule"):
        return assess_cfrag_correctness(self, capsule)

    def attach_proof(self, e2, v2, u1, u2, z3, kfrag_signature, metadata):
        self.proof = CorrectnessProof(point_e2=e2,
                                      point_v2=v2,
                                      point_kfrag_commitment=u1,
                                      point_kfrag_pok=u2,
                                      bn_sig=z3,
                                      kfrag_signature=kfrag_signature,
                                      metadata=metadata,
                                      )

    def __bytes__(self):
        return self.to_bytes()
