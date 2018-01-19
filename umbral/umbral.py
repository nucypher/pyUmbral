from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.point import Point
from umbral.pre import UmbralParameters
from umbral.utils import hash_to_bn


class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.bn_id = id_
        self.bn_key = key
        self.point_eph_ni = x
        self.point_commitment = u1
        self.bn_sig1 = z1
        self.bn_sig2 = z2

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate a KFrag object from the serialized data.
        """
        id = BigNum.from_bytes(data[0:32], curve)
        key = BigNum.from_bytes(data[32:64], curve)
        eph_ni = Point.from_bytes(data[64:97], curve)
        commitment = Point.from_bytes(data[97:130], curve)
        sig1 = BigNum.from_bytes(data[130:162], curve)
        sig2 = BigNum.from_bytes(data[162:194], curve)

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

    def verify(self, pub_a, pub_b, params: UmbralParameters):

        u1 = self.point_commitment
        z1 = self.bn_sig1
        z2 = self.bn_sig2
        x = self.point_eph_ni

        g_y = (params.g * z2) + (pub_a * z1)

        return z1 == hash_to_bn([g_y, self.bn_id, pub_a, pub_b, u1, x], params)

    def is_consistent(self, vKeys, params: UmbralParameters):
        if vKeys is None or len(vKeys) == 0:
            raise ValueError('vKeys must not be empty')

        # TODO: change this!
        h = params.h
        lh_exp = h * self.bn_key

        rh_exp = vKeys[0]
        i_j = self.bn_id
        for vKey in vKeys[1:]:
            rh_exp = rh_exp + (vKey * i_j)
            i_j = i_j * self.bn_id

        return lh_exp == rh_exp

    def __bytes__(self):
        return self.to_bytes()


class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.point_eph_e2 = e2
        self.point_eph_v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate ChallengeResponse from serialized data.
        """
        e2 = Point.from_bytes(data[0:33], curve)
        v2 = Point.from_bytes(data[33:66], curve)
        kfrag_commitment = Point.from_bytes(data[66:99], curve)
        kfrag_pok = Point.from_bytes(data[99:132], curve)
        kfrag_sig1 = BigNum.from_bytes(data[132:164], curve)
        kfrag_sig2 = BigNum.from_bytes(data[164:196], curve)
        sig = BigNum.from_bytes(data[196:228], curve)

        return ChallengeResponse(e2, v2, kfrag_commitment, kfrag_pok,
                                 kfrag_sig1, kfrag_sig2, sig)

    def to_bytes(self):
        """
        Serialize the ChallengeResponse to a bytestring.
        """
        e2 = self.point_eph_e2.to_bytes()
        v2 = self.point_eph_v2.to_bytes()
        kfrag_commitment = self.point_kfrag_commitment.to_bytes()
        kfrag_pok = self.point_kfrag_pok.to_bytes()
        kfrag_sig1 = self.bn_kfrag_sig1.to_bytes()
        kfrag_sig2 = self.bn_kfrag_sig2.to_bytes()
        sig = self.bn_sig.to_bytes()

        return (e2 + v2 + kfrag_commitment + kfrag_pok + kfrag_sig1
                + kfrag_sig2 + sig)

    def __bytes__(self):
        return self.to_bytes()
