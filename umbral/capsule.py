from typing import Tuple

from .curve_point import CurvePoint
from .curve_scalar import CurveScalar
from .dem import kdf
from .hashing import hash_capsule_points
from .keys import PublicKey, SecretKey
from .params import PARAMETERS
from .serializable import Serializable


class Capsule(Serializable):

    class NotValid(ValueError):
        """
        raised if the capsule does not pass verification.
        """

    def __init__(self, point_e: CurvePoint, point_v: CurvePoint, signature: CurveScalar):
        self.point_e = point_e
        self.point_v = point_v
        self.signature = signature

    @classmethod
    def __take__(cls, data: bytes) -> Tuple['Capsule', bytes]:
        (e, v, sig), data = cls.__take_types__(data, CurvePoint, CurvePoint, CurveScalar)

        capsule = cls(e, v, sig)
        if not capsule._verify():
            raise cls.NotValid("Capsule verification failed.")

        return capsule, data

    def __bytes__(self) -> bytes:
        return bytes(self.point_e) + bytes(self.point_v) + bytes(self.signature)

    @classmethod
    def from_public_key(cls, pk: PublicKey) -> Tuple['Capsule', CurvePoint]:
        g = CurvePoint.generator()

        priv_r = CurveScalar.random_nonzero()
        pub_r = g * priv_r

        priv_u = CurveScalar.random_nonzero()
        pub_u = g * priv_u

        h = hash_capsule_points(pub_r, pub_u)
        s = priv_u + (priv_r * h)

        shared_key = pk._point_key * (priv_r + priv_u)

        return cls(point_e=pub_r, point_v=pub_u, signature=s), shared_key

    def open_original(self, sk: SecretKey) -> CurvePoint:
        return (self.point_e + self.point_v) * sk.secret_scalar()

    def _components(self):
        return (self.point_e, self.point_v, self.signature)

    def _verify(self) -> bool:
        g = CurvePoint.generator()
        e, v, s = self._components()
        h = hash_capsule_points(e, v)
        return g * s == v + (e * h)

    def __eq__(self, other):
        return self._components() == other._components()

    def __hash__(self):
        return hash((self.__class__, bytes(self)))

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"
