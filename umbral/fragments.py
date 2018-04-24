from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve, default_params
from umbral.point import Point
from umbral.utils import get_curve_keysize_bytes

from io import BytesIO


class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.bn_id = id_
        self.bn_key = key
        self.point_eph_ni = x
        self.point_commitment = u1
        self.bn_sig1 = z1
        self.bn_sig2 = z2

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
        eph_ni = Point.from_bytes(data.read(key_size + 1), curve)
        commitment = Point.from_bytes(data.read(key_size + 1), curve)
        sig1 = BigNum.from_bytes(data.read(key_size), curve)
        sig2 = BigNum.from_bytes(data.read(key_size), curve)

        return cls(id, key, eph_ni, commitment, sig1, sig2)

    def to_bytes(self):
        """
        Serialize the KFrag into a bytestring.
        """
        id = self.bn_id.to_bytes()
        key = self.bn_key.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()
        commitment = self.point_commitment.to_bytes()
        sig1 = self.bn_sig1.to_bytes()
        sig2 = self.bn_sig2.to_bytes()

        return id + key + eph_ni + commitment + sig1 + sig2

    def verify(self, pub_a, pub_b, params: "UmbralParameters"=None):
        params = params if params is not None else default_params()

        u = params.u

        u1 = self.point_commitment
        z1 = self.bn_sig1
        z2 = self.bn_sig2
        x = self.point_eph_ni
        key = self.bn_key

        # We check that the commitment u1 is well-formed
        check_kfrag_1 = u1 == key * u

        # We check the Schnorr signature over the kfrag components
        g_y = (z2 * params.g) + (z1 * pub_a)
        check_kfrag_2 = z1 == BigNum.hash_to_bn(g_y, self.bn_id, pub_a, pub_b, u1, x, params=params)
        

        return check_kfrag_1 & check_kfrag_2

    def __bytes__(self):
        return self.to_bytes()


class CorrectnessProof(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3, metadata:bytes=None):
        self.point_eph_e2 = e2
        self.point_eph_v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3
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

        metadata = data.read() or None

        return cls(e2, v2, kfrag_commitment, kfrag_pok, 
                   kfrag_sig1, kfrag_sig2, sig, metadata=metadata)

    def to_bytes(self) -> bytes:
        """
        Serialize the CorrectnessProof to a bytestring.
        """
        e2 = self.point_eph_e2.to_bytes()
        v2 = self.point_eph_v2.to_bytes()
        kfrag_commitment = self.point_kfrag_commitment.to_bytes()
        kfrag_pok = self.point_kfrag_pok.to_bytes()
        kfrag_sig1 = self.bn_kfrag_sig1.to_bytes()
        kfrag_sig2 = self.bn_kfrag_sig2.to_bytes()
        sig = self.bn_sig.to_bytes()

        result = e2            \
            + v2               \
            + kfrag_commitment \
            + kfrag_pok        \
            + kfrag_sig1       \
            + kfrag_sig2       \
            + sig              

        result += self.metadata or b''

        return result

    def __bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self, e1, v1, id_, x, proof: CorrectnessProof=None):
        self.point_eph_e1 = e1
        self.point_eph_v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x
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
        eph_ni = Point.from_bytes(data.read(key_size + 1), curve)

        proof = data.read() or None
        proof = CorrectnessProof.from_bytes(proof, curve) if proof else None

        return cls(e1, v1, kfrag_id, eph_ni, proof)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self.point_eph_e1.to_bytes()
        v1 = self.point_eph_v1.to_bytes()
        kfrag_id = self.bn_kfrag_id.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()

        serialized_cfrag = e1 + v1 + kfrag_id + eph_ni

        if self.proof is not None:
            serialized_cfrag += self.proof.to_bytes()

        return serialized_cfrag

    def __bytes__(self):
        return self.to_bytes()


