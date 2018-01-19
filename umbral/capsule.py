from cryptography.hazmat.primitives.asymmetric import ec

from umbral.bignum import BigNum
from umbral.point import Point
from umbral.pre import UmbralParameters
from umbral.pre import PRE
from umbral.utils import lambda_coeff, hash_to_bn


class CapsuleFrag(object):
    def __init__(self, e1, v1, id_, x):
        self.point_eph_e1 = e1
        self.point_eph_v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiates a CapsuleFrag object from the serialized data.
        """
        e1 = Point.from_bytes(data[0:33], curve)
        v1 = Point.from_bytes(data[33:66], curve)
        kfrag_id = BigNum.from_bytes(data[66:98], curve)
        eph_ni = Point.from_bytes(data[98:131], curve)

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


class Capsule(object):
    def __init__(self,
                 point_eph_e=None,
                 point_eph_v=None,
                 bn_sig=None,
                 e_prime=None,
                 v_prime=None,
                 noninteractive_point=None):

        if not point_eph_e and not e_prime:
            raise ValueError(
                "Can't make a Capsule from nothing.  Pass either Alice's data (ie, point_eph_e) or Bob's (e_prime). \
                Passing both is also fine.")

        self._point_eph_e = point_eph_e
        self._point_eph_v = point_eph_v
        self._bn_sig = bn_sig

        self._point_eph_e_prime = e_prime
        self._point_eph_v_prime = v_prime
        self._point_noninteractive = noninteractive_point

        self.cfrags = {}
        self._contents = None

    @classmethod
    def from_original_bytes(cls, data: bytes, curve: ec.EllipticCurve):
        """
        Instantiates a Capsule object from the serialized data.
        """
        eph_e = Point.from_bytes(data[0:33], curve)
        eph_v = Point.from_bytes(data[33:66], curve)
        sig = BigNum.from_bytes(data[66:98], curve)

        return cls(eph_e, eph_v, sig)

    @classmethod
    def from_reconstructed_bytes(cls, data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate a Capsule from serialized data after reconstruction has occurred.

        The most obvious use case is Bob affixing at least m cFrags and then serializing the Capsule.
        """
        # TODO: Seems like a job for BytestringSplitter ?
        e_prime = Point.from_bytes(data[0:33], curve)
        v_prime = Point.from_bytes(data[33:66], curve)
        eph_ni = Point.from_bytes(data[66:99], curve)

        return cls(e_prime=e_prime, v_prime=v_prime, noninteractive_point=eph_ni)

    @property
    def contents(self):
        return self._contents

    def to_bytes(self):
        """
        Serialize the Capsule into a bytestring.
        """
        eph_e = self._point_eph_e.to_bytes()
        eph_v = self._point_eph_v.to_bytes()
        sig = self._bn_sig.to_bytes()

        return eph_e + eph_v + sig

    def verify(self, params: UmbralParameters):

        e = self._point_eph_e
        v = self._point_eph_v
        s = self._bn_sig
        h = hash_to_bn([e, v], params)

        return params.g * s == v + (e * h)

    def attach_cfrag(self, cfrag: CapsuleFrag):
        self.cfrags[cfrag.bn_kfrag_id] = cfrag

    def open(self, pub_bob, priv_bob, pub_alice, force_reopen=False, pre=None):
        # TODO: Raise an error here if Bob hasn't gathered enough cFrags.
        if self.contents and not force_reopen:
            newly_opened = True
        else:
            self._reconstruct(pre=pre)
            if not pre:
                pre = PRE(UmbralParameters())
            self._contents = pre.decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, self)
            newly_opened = False
        return self.contents, newly_opened

    def original_components(self):
        return self._point_eph_e, self._point_eph_v, self._bn_sig

    def _reconstruct(self, pre):
        id_cfrag_pairs = list(self.cfrags.items())
        id_0, cfrag_0 = id_cfrag_pairs[0]
        if len(id_cfrag_pairs) > 1:
            ids = self.cfrags.keys()
            lambda_0 = lambda_coeff(id_0, ids)
            e = cfrag_0.point_eph_e1 * lambda_0
            v = cfrag_0.point_eph_v1 * lambda_0

            for id_i, cfrag in id_cfrag_pairs[1:]:
                lambda_i = lambda_coeff(id_i, ids)
                e = e + (cfrag.point_eph_e1 * lambda_i)
                v = v + (cfrag.point_eph_v1 * lambda_i)
        else:
            e = cfrag_0.point_eph_e1
            v = cfrag_0.point_eph_v1

        self._point_eph_e_prime = e
        self._point_eph_v_prime = v
        self._point_noninteractive = cfrag_0.point_eph_ni

    def _reconstructed_bytes(self):
        """
        Serialize the reconstruction components into a bytestring.
        """
        eph_e = self._point_eph_e_prime
        eph_v = self._point_eph_v_prime
        point_noninter = self._point_noninteractive

        return eph_e.to_bytes() + eph_v.to_bytes() + point_noninter.to_bytes()

    def __bytes__(self):
        self.to_bytes()
