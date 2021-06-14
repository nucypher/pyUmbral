from typing import TYPE_CHECKING, Tuple, Sequence

from .curve_point import CurvePoint
from .curve_scalar import CurveScalar
from .hashing import hash_capsule_points, hash_to_polynomial_arg, hash_to_shared_secret
from .keys import PublicKey, SecretKey
from .serializable import Serializable, Deserializable
if TYPE_CHECKING: # pragma: no cover
    from .capsule_frag import CapsuleFrag


def lambda_coeff(xs: Sequence[CurveScalar], i: int) -> CurveScalar:
    res = CurveScalar.one()
    for j, xs_j in enumerate(xs):
        if j != i:
            inv_diff = (xs_j - xs[i]).invert()
            res = (res * xs_j) * inv_diff
    return res


class Capsule(Serializable, Deserializable):
    """
    Encapsulated symmetric key.
    """

    def __init__(self, point_e: CurvePoint, point_v: CurvePoint, signature: CurveScalar):
        self.point_e = point_e
        self.point_v = point_v
        self.signature = signature

    _COMPONENT_TYPES = CurvePoint, CurvePoint, CurveScalar
    _SERIALIZED_SIZE = sum(tp.serialized_size() for tp in _COMPONENT_TYPES)

    @classmethod
    def serialized_size(cls):
        return cls._SERIALIZED_SIZE

    @classmethod
    def _from_exact_bytes(cls, data: bytes):
        capsule = cls(*cls._split(data, *cls._COMPONENT_TYPES))
        if not capsule._verify():
            raise ValueError("Capsule self-verification failed. Serialized data may be damaged.")
        return capsule

    def __bytes__(self):
        return bytes(self.point_e) + bytes(self.point_v) + bytes(self.signature)

    @classmethod
    def from_public_key(cls, delegating_pk: PublicKey) -> Tuple['Capsule', CurvePoint]:
        g = CurvePoint.generator()

        priv_r = CurveScalar.random_nonzero()
        pub_r = g * priv_r

        priv_u = CurveScalar.random_nonzero()
        pub_u = g * priv_u

        h = hash_capsule_points(pub_r, pub_u)
        s = priv_u + (priv_r * h)

        shared_key = delegating_pk._point_key * (priv_r + priv_u)

        return cls(point_e=pub_r, point_v=pub_u, signature=s), shared_key

    def open_original(self, delegating_sk: SecretKey) -> CurvePoint:
        return (self.point_e + self.point_v) * delegating_sk.secret_scalar()

    def open_reencrypted(self,
                         receiving_sk: SecretKey,
                         delegating_pk: PublicKey,
                         cfrags: Sequence['CapsuleFrag'],
                         ) -> CurvePoint:

        if len(cfrags) == 0:
            raise ValueError("Empty CapsuleFrag sequence")

        precursor = cfrags[0].precursor

        if len(set(cfrags)) != len(cfrags):
            raise ValueError("Some of the CapsuleFrags are repeated")

        if not all(cfrag.precursor == precursor for cfrag in cfrags[1:]):
            raise ValueError("CapsuleFrags are not pairwise consistent")

        pub_key = receiving_sk.public_key().point()
        dh_point = precursor * receiving_sk.secret_scalar()

        # Combination of CFrags via Shamir's Secret Sharing reconstruction
        lc = [hash_to_polynomial_arg(precursor, pub_key, dh_point, cfrag.kfrag_id)
              for cfrag in cfrags]

        e_primes = []
        v_primes = []
        for i, cfrag in enumerate(cfrags):
            lambda_i = lambda_coeff(lc, i)
            e_primes.append(cfrag.point_e1 * lambda_i)
            v_primes.append(cfrag.point_v1 * lambda_i)
        e_prime = sum(e_primes[1:], e_primes[0])
        v_prime = sum(v_primes[1:], v_primes[0])

        # Secret value 'd' allows to make Umbral non-interactive
        d = hash_to_shared_secret(precursor, pub_key, dh_point)

        s = self.signature
        h = hash_capsule_points(self.point_e, self.point_v)

        orig_pub_key = delegating_pk.point()

        # TODO: check for d == 0? Or just let if fail?
        inv_d = d.invert()
        if orig_pub_key * (s * inv_d) != (e_prime * h) + v_prime:
            raise ValueError("Internal validation failed")

        return (e_prime + v_prime) * d

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
