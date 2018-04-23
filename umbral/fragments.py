from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve, default_params
from umbral.point import Point
from umbral.utils import get_curve_keysize_bytes

from io import BytesIO


class KFrag(object):
    def __init__(self, bn_id, bn_key, point_noninteractive, 
                 point_commitment, bn_sig1, bn_sig2):
        self._bn_id = bn_id
        self._bn_key = bn_key
        self._point_noninteractive = point_noninteractive
        self._point_commitment = point_commitment
        self._bn_sig1 = bn_sig1
        self._bn_sig2 = bn_sig2

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiate a KFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        id = BigNum.from_bytes(data.read(key_size), curve)
        key = BigNum.from_bytes(data.read(key_size), curve)
        ni = Point.from_bytes(data.read(key_size + 1), curve)
        commitment = Point.from_bytes(data.read(key_size + 1), curve)
        sig1 = BigNum.from_bytes(data.read(key_size), curve)
        sig2 = BigNum.from_bytes(data.read(key_size), curve)

        return cls(id, key, ni, commitment, sig1, sig2)

    def to_bytes(self):
        """
        Serialize the KFrag into a bytestring.
        """
        id = self._bn_id.to_bytes()
        key = self._bn_key.to_bytes()
        ni = self._point_noninteractive.to_bytes()
        commitment = self._point_commitment.to_bytes()
        sig1 = self._bn_sig1.to_bytes()
        sig2 = self._bn_sig2.to_bytes()

        return id + key + ni + commitment + sig1 + sig2

    def verify(self, pub_a, pub_b, params: "UmbralParameters"=None):
        params = params if params is not None else default_params()

        u = params.u

        u1 = self._point_commitment
        z1 = self._bn_sig1
        z2 = self._bn_sig2
        x = self._point_noninteractive
        key = self._bn_key

        # We check that the commitment u1 is well-formed
        correct_commitment = u1 == key * u

        # We check the Schnorr signature over the kfrag components
        g_y = (z2 * params.g) + (z1 * pub_a)

        kfrag_components = [g_y, self._bn_id, pub_a, pub_b, u1, x]
        valid_kfrag_signature = z1 == BigNum.hash_to_bn(*kfrag_components, params=params)

        return correct_commitment & valid_kfrag_signature

    def __bytes__(self):
        return self.to_bytes()


class CorrectnessProof(object):
    def __init__(self, point_e2, point_v2, point_kfrag_commitment, 
                 point_kfrag_pok, bn_kfrag_sig1, bn_kfrag_sig2, bn_sig, 
                 metadata:bytes=None):
        self._point_e2 = point_e2
        self._point_v2 = point_v2
        self._point_kfrag_commitment = point_kfrag_commitment
        self._point_kfrag_pok = point_kfrag_pok
        self._bn_kfrag_sig1 = bn_kfrag_sig1
        self._bn_kfrag_sig2 = bn_kfrag_sig2
        self._bn_sig = bn_sig
        self.metadata = metadata

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve=None):
        """
        Instantiate CorrectnessProof from serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        e2 = Point.from_bytes(data.read(key_size + 1), curve)
        v2 = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_commitment = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_pok = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_sig1 = BigNum.from_bytes(data.read(key_size), curve)
        kfrag_sig2 = BigNum.from_bytes(data.read(key_size), curve)
        sig = BigNum.from_bytes(data.read(key_size), curve)

        metadata = data.read()
        if metadata == bytes(0):
            metadata = None

        return cls(e2, v2, kfrag_commitment, kfrag_pok, 
                   kfrag_sig1, kfrag_sig2, sig, metadata=metadata)

    def to_bytes(self) -> bytes:
        """
        Serialize the CorrectnessProof to a bytestring.
        """
        e2 = self._point_e2.to_bytes()
        v2 = self._point_v2.to_bytes()
        kfrag_commitment = self._point_kfrag_commitment.to_bytes()
        kfrag_pok = self._point_kfrag_pok.to_bytes()
        kfrag_sig1 = self._bn_kfrag_sig1.to_bytes()
        kfrag_sig2 = self._bn_kfrag_sig2.to_bytes()
        sig = self._bn_sig.to_bytes()

        result = e2            \
            + v2               \
            + kfrag_commitment \
            + kfrag_pok        \
            + kfrag_sig1       \
            + kfrag_sig2       \
            + sig              

        if self.metadata is not None:
            result = result + self.metadata

        return result

    def __bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self, point_e1, point_v1, bn_kfrag_id, point_noninteractive, 
                 proof: CorrectnessProof=None):
        self._point_e1 = point_e1
        self._point_v1 = point_v1
        self._bn_kfrag_id = bn_kfrag_id
        self._point_noninteractive = point_noninteractive
        self.proof = proof

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        e1 = Point.from_bytes(data.read(key_size + 1), curve)
        v1 = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_id = BigNum.from_bytes(data.read(key_size), curve)
        ni = Point.from_bytes(data.read(key_size + 1), curve)

        proof = data.read()
        proof = CorrectnessProof.from_bytes(proof, curve) if proof != bytes(0) else None

        return cls(e1, v1, kfrag_id, ni, proof)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self._point_e1.to_bytes()
        v1 = self._point_v1.to_bytes()
        kfrag_id = self._bn_kfrag_id.to_bytes()
        ni = self._point_noninteractive.to_bytes()

        serialized_cfrag = e1 + v1 + kfrag_id + ni

        if self.proof is not None:
            serialized_cfrag += self.proof.to_bytes()

        return serialized_cfrag

    def __bytes__(self):
        return self.to_bytes()


