from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum, hash_to_bn
from umbral.config import default_curve, default_params
from umbral.point import Point
from umbral.utils import get_curve_keysize_bytes, AbstractCryptoEntity


from io import BytesIO


class KFrag(AbstractCryptoEntity):
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
        check_kfrag_2 = z1 == hash_to_bn([g_y, self.bn_id, pub_a, pub_b, u1, x], params)


        return check_kfrag_1 & check_kfrag_2

class CapsuleFrag(AbstractCryptoEntity):
    def __init__(self, e1, v1, id_, x):
        self.point_eph_e1 = e1
        self.point_eph_v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x

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

        return cls(e1, v1, kfrag_id, eph_ni)

    def to_bytes(self):
        """
        Serialize the CapsuleFrag into a bytestring.
        """
        e1 = self.point_eph_e1.to_bytes()
        v1 = self.point_eph_v1.to_bytes()
        kfrag_id = self.bn_kfrag_id.to_bytes()
        eph_ni = self.point_eph_ni.to_bytes()

        return e1 + v1 + kfrag_id + eph_ni
