from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.config import default_curve, default_params
from umbral.point import Point
from umbral.utils import hash_to_bn

from io import BytesIO


class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.bn_id = id_
        self.bn_key = key
        self.point_eph_ni = x
        self.point_commitment = u1
        self.bn_sig1 = z1
        self.bn_sig2 = z2

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiate a KFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = curve.key_size // 8
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        id = BigNum.from_bytes(data.read(key_size), curve)
        key = BigNum.from_bytes(data.read(key_size), curve)
        eph_ni = Point.from_bytes(data.read(key_size + 1), curve)
        commitment = Point.from_bytes(data.read(key_size + 1), curve)
        sig1 = BigNum.from_bytes(data.read(key_size), curve)
        sig2 = BigNum.from_bytes(data.read(key_size), curve)

        return KFrag(id, key, eph_ni, commitment, sig1, sig2)

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

        u1 = self.point_commitment
        z1 = self.bn_sig1
        z2 = self.bn_sig2
        x = self.point_eph_ni

        g_y = (z2 * params.g) + (z1 * pub_a)

        return z1 == hash_to_bn([g_y, self.bn_id, pub_a, pub_b, u1, x], params)

    def is_consistent(self, vKeys, params: "UmbralParameters"=None):
        params = params if params is not None else default_params()

        if vKeys is None or len(vKeys) == 0:
            raise ValueError('vKeys must not be empty')

        h = params.h
        lh_exp = self.bn_key * h

        rh_exp = vKeys[0]
        i_j = self.bn_id
        for vKey in vKeys[1:]:
            rh_exp = rh_exp + (i_j * vKey)
            i_j = i_j * self.bn_id

        return lh_exp == rh_exp

    def __bytes__(self):
        return self.to_bytes()


class CapsuleFrag(object):
    def __init__(self, e1, v1, id_, x):
        self.point_eph_e1 = e1
        self.point_eph_v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = curve.key_size // 8
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        e1 = Point.from_bytes(data.read(key_size + 1), curve)
        v1 = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_id = BigNum.from_bytes(data.read(key_size), curve)
        eph_ni = Point.from_bytes(data.read(key_size + 1), curve)

        return CapsuleFrag(e1, v1, kfrag_id, eph_ni)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self.point_eph_e1.to_bytes()
        v1 = self.point_eph_v1.to_bytes()
        kfrag_id = self.bn_kfrag_id.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()

        return e1 + v1 + kfrag_id + eph_ni

    def __bytes__(self):
        return self.to_bytes()
