from typing import Optional, Tuple

from .capsule import Capsule
from .curve_point import CurvePoint
from .curve_scalar import CurveScalar
from .errors import VerificationError
from .hashing import hash_to_cfrag_verification, kfrag_signature_message
from .keys import PublicKey
from .key_frag import KeyFrag, KeyFragID
from .params import PARAMETERS
from .serializable import Serializable
from .signing import Signature


class CapsuleFragProof(Serializable):

    def __init__(self,
                 point_e2: CurvePoint,
                 point_v2: CurvePoint,
                 kfrag_commitment: CurvePoint,
                 kfrag_pok: CurvePoint,
                 signature: CurveScalar,
                 kfrag_signature: Signature,
                 ):

        self.point_e2 = point_e2
        self.point_v2 = point_v2
        self.kfrag_commitment = kfrag_commitment
        self.kfrag_pok = kfrag_pok
        self.signature = signature
        self.kfrag_signature = kfrag_signature

    def _components(self):
        return (self.point_e2, self.point_v2, self.kfrag_commitment,
                self.kfrag_pok, self.signature, self.kfrag_signature)

    def __eq__(self, other):
        return self._components() == other._components()

    @classmethod
    def __take__(cls, data):
        types = [CurvePoint, CurvePoint, CurvePoint, CurvePoint, CurveScalar, Signature]
        components, data = cls.__take_types__(data, *types)
        return cls(*components), data

    def __bytes__(self):
        return (bytes(self.point_e2) +
                bytes(self.point_v2) +
                bytes(self.kfrag_commitment) +
                bytes(self.kfrag_pok) +
                bytes(self.signature) +
                bytes(self.kfrag_signature)
                )

    @classmethod
    def from_kfrag_and_cfrag(cls,
                             capsule: Capsule,
                             kfrag: KeyFrag,
                             cfrag_e1: CurvePoint,
                             cfrag_v1: CurvePoint,
                             metadata: Optional[bytes],
                             ) -> 'CapsuleFragProof':

        params = PARAMETERS

        rk = kfrag.key
        t = CurveScalar.random_nonzero()

        # Here are the formulaic constituents shared with `CapsuleFrag.verify()`.

        e = capsule.point_e
        v = capsule.point_v

        e1 = cfrag_e1
        v1 = cfrag_v1

        u = params.u
        u1 = kfrag.proof.commitment

        e2 = e * t
        v2 = v * t
        u2 = u * t

        h = hash_to_cfrag_verification([e, e1, e2, v, v1, v2, u, u1, u2], metadata)

        ###

        z3 = t + rk * h

        return cls(point_e2=e2,
                   point_v2=v2,
                   kfrag_commitment=u1,
                   kfrag_pok=u2,
                   signature=z3,
                   kfrag_signature=kfrag.proof.signature_for_receiver,
                   )


class CapsuleFrag(Serializable):
    """
    Re-encrypted fragment of :py:class:`Capsule`.
    """

    def __init__(self,
                 point_e1: CurvePoint,
                 point_v1: CurvePoint,
                 kfrag_id: KeyFragID,
                 precursor: CurvePoint,
                 proof: CapsuleFragProof,
                 ):

        self.point_e1 = point_e1
        self.point_v1 = point_v1
        self.kfrag_id = kfrag_id
        self.precursor = precursor
        self.proof = proof

    def _components(self):
        return (self.point_e1, self.point_v1, self.kfrag_id, self.precursor, self.proof)

    def __eq__(self, other):
        return self._components() == other._components()

    def __hash__(self):
        return hash((self.__class__, bytes(self)))

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    @classmethod
    def __take__(cls, data):
        types = CurvePoint, CurvePoint, KeyFragID, CurvePoint, CapsuleFragProof
        components, data = cls.__take_types__(data, *types)
        return cls(*components), data

    def __bytes__(self):
        return (bytes(self.point_e1) +
                bytes(self.point_v1) +
                bytes(self.kfrag_id) +
                bytes(self.precursor) +
                bytes(self.proof))

    @classmethod
    def reencrypted(cls,
                    capsule: Capsule,
                    kfrag: KeyFrag,
                    metadata: Optional[bytes] = None,
                    ) -> 'CapsuleFrag':
        rk = kfrag.key
        e1 = capsule.point_e * rk
        v1 = capsule.point_v * rk
        proof = CapsuleFragProof.from_kfrag_and_cfrag(capsule, kfrag, e1, v1, metadata)

        return cls(point_e1=e1,
                   point_v1=v1,
                   kfrag_id=kfrag.id,
                   precursor=kfrag.precursor,
                   proof=proof,
                   )

    def verify(self,
               capsule: Capsule,
               verifying_pk: PublicKey,
               delegating_pk: PublicKey,
               receiving_pk: PublicKey,
               metadata: Optional[bytes] = None,
               ) -> 'VerifiedCapsuleFrag':
        """
        Verifies the validity of this fragment.

        ``metadata`` should coincide with the one given to :py:func:`reencrypt`.
        """

        params = PARAMETERS

        # Here are the formulaic constituents shared with
        # `CapsuleFragProof.from_kfrag_and_cfrag`.

        e = capsule.point_e
        v = capsule.point_v

        e1 = self.point_e1
        v1 = self.point_v1

        u = params.u
        u1 = self.proof.kfrag_commitment

        e2 = self.proof.point_e2
        v2 = self.proof.point_v2
        u2 = self.proof.kfrag_pok

        h = hash_to_cfrag_verification([e, e1, e2, v, v1, v2, u, u1, u2], metadata)

        ###

        precursor = self.precursor
        kfrag_id = self.kfrag_id

        kfrag_message = kfrag_signature_message(kfrag_id=self.kfrag_id,
                                                commitment=self.proof.kfrag_commitment,
                                                precursor=self.precursor,
                                                maybe_delegating_pk=delegating_pk,
                                                maybe_receiving_pk=receiving_pk)

        if not self.proof.kfrag_signature.verify(verifying_pk, kfrag_message):
            raise VerificationError("Invalid KeyFrag signature")

        z = self.proof.signature

        # TODO: if one or more of the values here are incorrect,
        # we'll get the wrong `h` (since they're all hashed into it),
        # so perhaps it's enough to check only one of these equations.
        # See https://github.com/nucypher/rust-umbral/issues/46 for details.
        correct_reencryption_of_e = e * z == e2 + e1 * h
        correct_reencryption_of_v = v * z == v2 + v1 * h
        correct_rk_commitment = u * z == u2 + u1 * h

        if not (correct_reencryption_of_e and correct_reencryption_of_v and correct_rk_commitment):
            raise VerificationError("Failed to verify reencryption proof")

        return VerifiedCapsuleFrag(self)


class VerifiedCapsuleFrag:
    """
    Verified capsule frag, good for decryption.
    Can be cast to ``bytes``, but cannot be deserialized from bytes directly.
    It can only be obtained from :py:meth:`CapsuleFrag.verify`.
    """

    def __init__(self, cfrag: CapsuleFrag):
        self.cfrag = cfrag

    def __bytes__(self):
        return bytes(self.cfrag)

    def __eq__(self, other):
        return self.cfrag == other.cfrag

    def __hash__(self):
        return hash((self.__class__, bytes(self)))

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"
