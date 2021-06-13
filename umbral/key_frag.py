import os
from typing import List, Optional, Tuple, Type

from .curve_point import CurvePoint
from .curve_scalar import CurveScalar
from .errors import VerificationError
from .hashing import hash_to_shared_secret, kfrag_signature_message, hash_to_polynomial_arg
from .keys import PublicKey, SecretKey
from .params import PARAMETERS
from .serializable import (
    Serializable, Deserializable, HasSerializedSize,
    bool_bytes, bool_serialized_size)
from .signing import Signature, Signer


class KeyFragID(Serializable, Deserializable):

    __SIZE = 32

    def __init__(self, id_: bytes):
        self._id = id_

    def __eq__(self, other):
        return self._id == other._id

    @classmethod
    def random(cls) -> 'KeyFragID':
        return cls(os.urandom(cls.__SIZE))

    @classmethod
    def serialized_size(cls):
        return cls.__SIZE

    @classmethod
    def _from_exact_bytes(cls, data):
        return cls(data)

    def __bytes__(self):
        return self._id


class KeyFragProof(Serializable, Deserializable):

    @classmethod
    def from_base(cls,
                  base: 'KeyFragBase',
                  kfrag_id: KeyFragID,
                  kfrag_key: CurveScalar,
                  sign_delegating_key: bool,
                  sign_receiving_key: bool,
                  ) -> 'KeyFragProof':

        params = PARAMETERS

        kfrag_precursor = base.precursor
        signer = base.signer
        delegating_pk = base.delegating_pk
        receiving_pk = base.receiving_pk

        commitment = params.u * kfrag_key

        message_for_receiver = kfrag_signature_message(kfrag_id=kfrag_id,
                                                       commitment=commitment,
                                                       precursor=kfrag_precursor,
                                                       maybe_delegating_pk=delegating_pk,
                                                       maybe_receiving_pk=receiving_pk,
                                                       )
        signature_for_receiver = signer.sign(message_for_receiver)

        maybe_delegating_pk = delegating_pk if sign_delegating_key else None
        maybe_receiving_pk = receiving_pk if sign_receiving_key else None
        message_for_proxy = kfrag_signature_message(kfrag_id=kfrag_id,
                                                    commitment=commitment,
                                                    precursor=kfrag_precursor,
                                                    maybe_delegating_pk=maybe_delegating_pk,
                                                    maybe_receiving_pk=maybe_receiving_pk,
                                                    )
        signature_for_proxy = signer.sign(message_for_proxy)

        return cls(commitment,
                   signature_for_proxy,
                   signature_for_receiver,
                   sign_delegating_key,
                   sign_receiving_key)

    def __init__(self,
                 commitment: CurvePoint,
                 signature_for_proxy: Signature,
                 signature_for_receiver: Signature,
                 delegating_key_signed: bool,
                 receiving_key_signed: bool
                 ):

        self.commitment = commitment
        self.signature_for_proxy = signature_for_proxy
        self.signature_for_receiver = signature_for_receiver
        self.delegating_key_signed = delegating_key_signed
        self.receiving_key_signed = receiving_key_signed

    def _components(self):
        return (self.commitment,
                self.signature_for_proxy,
                self.signature_for_receiver,
                self.delegating_key_signed,
                self.receiving_key_signed)

    def __eq__(self, other):
        return self._components() == other._components()

    _SERIALIZED_SIZE = (CurvePoint.serialized_size() +
                        Signature.serialized_size() * 2 +
                        bool_serialized_size() * 2)

    @classmethod
    def serialized_size(cls):
        return cls._SERIALIZED_SIZE

    @classmethod
    def _from_exact_bytes(cls, data):
        types = [CurvePoint, Signature, Signature, bool, bool]
        return cls(*cls._split(data, *types))

    def __bytes__(self):
        return (bytes(self.commitment) +
                bytes(self.signature_for_proxy) +
                bytes(self.signature_for_receiver) +
                bool_bytes(self.delegating_key_signed) +
                bool_bytes(self.receiving_key_signed)
                )


# Coefficients of the generating polynomial
def poly_eval(coeffs: List[CurveScalar], x: CurveScalar) -> CurveScalar:
    result = coeffs[-1]
    for coeff in reversed(coeffs[:-1]):
        result = (result * x) + coeff
    return result


class KeyFrag(Serializable, Deserializable):
    """
    A signed fragment of the delegating key.
    """

    def __init__(self,
                 id_: KeyFragID,
                 key: CurveScalar,
                 precursor: CurvePoint,
                 proof: KeyFragProof):
        self.id = id_
        self.key = key
        self.precursor = precursor
        self.proof = proof

    def _components(self):
        return self.id, self.key, self.precursor, self.proof

    _COMPONENT_TYPES: Tuple[Type[HasSerializedSize], ...] = (
        KeyFragID, CurveScalar, CurvePoint, KeyFragProof)
    _SERIALIZED_SIZE = sum(tp.serialized_size() for tp in _COMPONENT_TYPES)

    @classmethod
    def serialized_size(cls):
        return cls._SERIALIZED_SIZE

    @classmethod
    def _from_exact_bytes(cls, data):
        return cls(*cls._split(data, *cls._COMPONENT_TYPES))

    def __bytes__(self):
        return b''.join(bytes(comp) for comp in self._components())

    def __eq__(self, other):
        return self._components() == other._components()

    def __hash__(self):
        return hash((self.__class__, bytes(self)))

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"

    @classmethod
    def from_base(cls,
                  base: 'KeyFragBase',
                  sign_delegating_key: bool,
                  sign_receiving_key: bool,
                  ) -> 'KeyFrag':

        kfrag_id = KeyFragID.random()

        # The index of the re-encryption key share (which in Shamir's Secret
        # Sharing corresponds to x in the tuple (x, f(x)), with f being the
        # generating polynomial), is used to prevent reconstruction of the
        # re-encryption key without Bob's intervention
        share_index = hash_to_polynomial_arg(base.precursor,
                                             base.receiving_pk.point(),
                                             base.dh_point,
                                             kfrag_id,
                                             )

        # The re-encryption key share is the result of evaluating the generating
        # polynomial for the index value
        rk = poly_eval(base.coefficients, share_index)

        proof = KeyFragProof.from_base(base,
                                       kfrag_id,
                                       rk,
                                       sign_delegating_key,
                                       sign_receiving_key,
                                       )

        return cls(kfrag_id, rk, base.precursor, proof)

    def verify(self,
               verifying_pk: PublicKey,
               delegating_pk: Optional[PublicKey] = None,
               receiving_pk: Optional[PublicKey] = None,
               ) -> 'VerifiedKeyFrag':
        """
        Verifies the validity of this fragment.

        If the delegating and/or receiving key were not signed in :py:func:`generate_kfrags`,
        but are given to this function, they are ignored.
        """

        u = PARAMETERS.u

        kfrag_id = self.id
        key = self.key
        commitment = self.proof.commitment
        precursor = self.precursor

        if commitment != u * key:
            raise VerificationError("Invalid kfrag commitment")

        if self.proof.delegating_key_signed and not bool(delegating_pk):
            raise VerificationError("A signature of a delegating key was included in this kfrag, "
                                    "but the key is not provided")

        if self.proof.receiving_key_signed and not bool(receiving_pk):
            raise VerificationError("A signature of a receiving key was included in this kfrag, "
                                    "but the key is not provided")

        delegating_pk = delegating_pk if self.proof.delegating_key_signed else None
        receiving_pk = receiving_pk if self.proof.receiving_key_signed else None
        kfrag_message = kfrag_signature_message(kfrag_id=kfrag_id,
                                                commitment=commitment,
                                                precursor=precursor,
                                                maybe_delegating_pk=delegating_pk,
                                                maybe_receiving_pk=receiving_pk)
        if not self.proof.signature_for_proxy.verify(verifying_pk, kfrag_message):
            raise VerificationError("Failed to verify the kfrag signature")

        return VerifiedKeyFrag(self)


class VerifiedKeyFrag(Serializable):
    """
    Verified kfrag, good for reencryption.
    Can be cast to ``bytes``, but cannot be deserialized from bytes directly.
    It can only be obtained from :py:meth:`KeyFrag.verify`.
    """

    def __init__(self, kfrag: KeyFrag):
        self.kfrag = kfrag

    def __bytes__(self):
        return bytes(self.kfrag)

    @classmethod
    def serialized_size(cls):
        return KeyFrag.serialized_size()

    @classmethod
    def from_verified_bytes(cls, data) -> 'VerifiedKeyFrag':
        """
        Restores a verified keyfrag directly from serialized bytes,
        skipping :py:meth:`KeyFrag.verify` call.

        Intended for internal storage;
        make sure that the bytes come from a trusted source.
        """
        kfrag = KeyFrag.from_bytes(data)
        return cls(kfrag)

    def __eq__(self, other):
        return self.kfrag == other.kfrag

    def __hash__(self):
        return hash((self.__class__, bytes(self)))

    def __str__(self):
        return f"{self.__class__.__name__}:{bytes(self).hex()[:16]}"


class KeyFragBase:

    def __init__(self,
                 delegating_sk: SecretKey,
                 receiving_pk: PublicKey,
                 signer: Signer,
                 threshold: int,
                 ):

        if threshold <= 0:
            raise ValueError(f"`threshold` must be larger than 0 (given: {threshold})")

        g = CurvePoint.generator()

        delegating_pk = delegating_sk.public_key()

        receiving_pk_point = receiving_pk.point()

        while True:
            # The precursor point is used as an ephemeral public key in a DH key exchange,
            # and the resulting shared secret 'dh_point' is used to derive other secret values
            private_precursor = CurveScalar.random_nonzero()
            precursor = g * private_precursor

            dh_point = receiving_pk_point * private_precursor

            # Secret value 'd' allows to make Umbral non-interactive
            d = hash_to_shared_secret(precursor, receiving_pk_point, dh_point)

            # At the moment we cannot statically ensure `d` is not zero,
            # but we need it to be non-zero for the algorithm to work.
            if not d.is_zero():
                break

        # Coefficients of the generating polynomial
        # `invert()` is guaranteed to work because `d` is nonzero.
        coefficients = [
            delegating_sk.secret_scalar() * d.invert(),
            *[CurveScalar.random_nonzero() for _ in range(threshold-1)]]

        self.signer = signer
        self.precursor = precursor
        self.dh_point = dh_point
        self.delegating_pk = delegating_pk
        self.receiving_pk = receiving_pk
        self.coefficients = coefficients
