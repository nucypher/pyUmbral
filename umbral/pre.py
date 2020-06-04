"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import typing
from typing import Dict, List, Optional, Tuple, Union, Any, Sequence

from bytestring_splitter import BytestringSplitter
from cryptography.exceptions import InvalidTag
from constant_sorrow import constants

from umbral.cfrags import CapsuleFrag
from umbral.config import default_curve
from umbral.curve import Curve
from umbral.curvebn import CurveBN
from umbral.dem import UmbralDEM, DEM_KEYSIZE, DEM_NONCE_SIZE
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.kfrags import KFrag, NO_KEY, DELEGATING_ONLY, RECEIVING_ONLY, DELEGATING_AND_RECEIVING
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.random_oracles import kdf, hash_to_curvebn
from umbral.signing import Signer
from umbral.utils import poly_eval, lambda_coeff


class GenericUmbralError(Exception):
    pass


class UmbralCorrectnessError(GenericUmbralError):
    def __init__(self, message: str, offending_cfrags: List[CapsuleFrag]) -> None:
        super().__init__(message)
        self.offending_cfrags = offending_cfrags


class UmbralDecryptionError(GenericUmbralError):
    def __init__(self) -> None:
        super().__init__("Decryption of ciphertext failed: "
                         "either someone tampered with the ciphertext or "
                         "you are using an incorrect decryption key.")


class Capsule:

    def __init__(self,
                 params: UmbralParameters,
                 point_e: Point,
                 point_v: Point,
                 bn_sig: CurveBN,
                 ) -> None:

        self.params = params

        if not all((isinstance(point_e, Point),
                    isinstance(point_v, Point),
                    isinstance(bn_sig, CurveBN))):
            raise TypeError("Need valid point_e, point_v, and bn_sig to make a Capsule.")

        self.point_e = point_e
        self.point_v = point_v
        self.bn_sig = bn_sig

    class NotValid(ValueError):
        """
        raised if the capsule does not pass verification.
        """

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        """
        Returns the size (in bytes) of a Capsule given the curve.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        return (bn_size * 1) + (point_size * 2)

    @classmethod
    def from_bytes(cls, capsule_bytes: bytes, params: UmbralParameters) -> 'Capsule':
        """
        Instantiates a Capsule object from the serialized data.
        """
        curve = params.curve

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)
        arguments = {'curve': curve}

        if len(capsule_bytes) == cls.expected_bytes_length(curve):
            splitter = BytestringSplitter(
                (Point, point_size, arguments),  # point_e
                (Point, point_size, arguments),  # point_v
                (CurveBN, bn_size, arguments)  # bn_sig
            )
        else:
            raise ValueError("Byte string does not have a valid length for a Capsule")

        components = splitter(capsule_bytes)
        return cls(params, *components)

    def with_correctness_keys(self,
                             delegating: UmbralPublicKey,
                             receiving: UmbralPublicKey,
                             verifying: UmbralPublicKey,
                             ) -> 'PreparedCapsule':
        return PreparedCapsule(self, delegating, receiving, verifying)

    def to_bytes(self) -> bytes:
        """
        Serialize the Capsule into a bytestring.
        """
        e, v, s = self.components()
        return e.to_bytes() + v.to_bytes() + s.to_bytes()

    def verify(self) -> bool:

        g = self.params.g
        e, v, s = self.components()
        h = hash_to_curvebn(e, v, params=self.params)

        result = s * g == v + (h * e)      # type: bool
        return result

    def components(self) -> Tuple[Point, Point, CurveBN]:
        return self.point_e, self.point_v, self.bn_sig

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __eq__(self, other) -> bool:
        """
        Each component is compared to its counterpart in constant time per the __eq__ of Point and CurveBN.
        """
        return hasattr(other, "components") and self.components() == other.components() and all(self.components())

    @typing.no_type_check
    def __hash__(self) -> int:
        # In case this isn't obvious, don't use this as a secure hash.  Use BLAKE2b or something.
        component_bytes = tuple(component.to_bytes() for component in self.components())
        return hash(component_bytes)

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, hex(int(self.bn_sig))[2:17])


class PreparedCapsule:

    def __init__(self,
                 capsule: Capsule,
                 delegating_key: UmbralPublicKey,
                 receiving_key: UmbralPublicKey,
                 verifying_key: UmbralPublicKey):

        def check_key(key):
            if capsule.params != key.params:
                raise TypeError("You are trying to set a key with different UmbralParameters.")

        check_key(delegating_key)
        check_key(receiving_key)
        check_key(verifying_key)

        self.capsule = capsule
        self.delegating_key = delegating_key
        self.receiving_key = receiving_key
        self.verifying_key = verifying_key

        self._attached_cfrags = set()    # type: set

    def verify(self):
        return self.capsule.verify()

    def verify_cfrag(self, cfrag) -> bool:
        return cfrag.verify_correctness(capsule=self.capsule,
                                        delegating_pubkey=self.delegating_key,
                                        receiving_pubkey=self.receiving_key,
                                        signing_pubkey=self.verifying_key)

    def verify_kfrag(self, kfrag) -> bool:
        return kfrag.verify(params=self.capsule.params,
                            signing_pubkey=self.verifying_key,
                            delegating_pubkey=self.delegating_key,
                            receiving_pubkey=self.receiving_key)


def generate_kfrags(delegating_privkey: UmbralPrivateKey,
                    receiving_pubkey: UmbralPublicKey,
                    threshold: int,
                    N: int,
                    signer: Signer,
                    sign_delegating_key: Optional[bool] = True,
                    sign_receiving_key: Optional[bool] = True,
                    ) -> List[KFrag]:
    """
    Creates a re-encryption key from Alice's delegating public key to Bob's
    receiving public key, and splits it in KFrags, using Shamir's Secret Sharing.
    Requires a threshold number of KFrags out of N.

    Returns a list of N KFrags
    """

    if threshold <= 0 or threshold > N:
        raise ValueError('Arguments threshold and N must satisfy 0 < threshold <= N')

    if delegating_privkey.params != receiving_pubkey.params:
        raise ValueError("Keys must have the same parameter set.")

    params = delegating_privkey.params

    g = params.g

    delegating_pubkey = delegating_privkey.get_pubkey()

    bob_pubkey_point = receiving_pubkey.point_key

    # The precursor point is used as an ephemeral public key in a DH key exchange,
    # and the resulting shared secret 'dh_point' is used to derive other secret values
    private_precursor = CurveBN.gen_rand(params.curve)
    precursor = private_precursor * g   # type: Any

    dh_point = private_precursor * bob_pubkey_point

    # Secret value 'd' allows to make Umbral non-interactive
    d = hash_to_curvebn(precursor,
                        bob_pubkey_point,
                        dh_point,
                        bytes(constants.NON_INTERACTIVE),
                        params=params)

    # Coefficients of the generating polynomial
    coefficients = [delegating_privkey.bn_key * (~d)]
    coefficients += [CurveBN.gen_rand(params.curve) for _ in range(threshold - 1)]

    bn_size = CurveBN.expected_bytes_length(params.curve)

    kfrags = list()
    for _ in range(N):
        kfrag_id = os.urandom(bn_size)

        # The index of the re-encryption key share (which in Shamir's Secret
        # Sharing corresponds to x in the tuple (x, f(x)), with f being the
        # generating polynomial), is used to prevent reconstruction of the
        # re-encryption key without Bob's intervention
        share_index = hash_to_curvebn(precursor,
                                      bob_pubkey_point,
                                      dh_point,
                                      bytes(constants.X_COORDINATE),
                                      kfrag_id,
                                      params=params)

        # The re-encryption key share is the result of evaluating the generating
        # polynomial for the index value
        rk = poly_eval(coefficients, share_index)

        commitment = rk * params.u  # type: Any

        validity_message_for_bob = (kfrag_id,
                                    delegating_pubkey,
                                    receiving_pubkey,
                                    commitment,
                                    precursor,
                                    )  # type: Any
        validity_message_for_bob = bytes().join(bytes(item) for item in validity_message_for_bob)
        signature_for_bob = signer(validity_message_for_bob)

        if sign_delegating_key and sign_receiving_key:
            mode = DELEGATING_AND_RECEIVING
        elif sign_delegating_key:
            mode = DELEGATING_ONLY
        elif sign_receiving_key:
            mode = RECEIVING_ONLY
        else:
            mode = NO_KEY

        validity_message_for_proxy = [kfrag_id, commitment, precursor, mode]  # type: Any

        if sign_delegating_key:
            validity_message_for_proxy.append(delegating_pubkey)
        if sign_receiving_key:
            validity_message_for_proxy.append(receiving_pubkey)

        validity_message_for_proxy = bytes().join(bytes(item) for item in validity_message_for_proxy)
        signature_for_proxy = signer(validity_message_for_proxy)

        kfrag = KFrag(identifier=kfrag_id,
                      bn_key=rk,
                      point_commitment=commitment,
                      point_precursor=precursor,
                      signature_for_proxy=signature_for_proxy,
                      signature_for_bob=signature_for_bob,
                      keys_in_signature=mode,
                      )

        kfrags.append(kfrag)

    return kfrags


def reencrypt(kfrag: KFrag,
              prepared_capsule: PreparedCapsule,
              metadata: Optional[bytes] = None,
              verify_kfrag: bool = True) -> CapsuleFrag:

    if not isinstance(prepared_capsule, PreparedCapsule):
        raise Capsule.NotValid

    if not prepared_capsule.verify():
        raise Capsule.NotValid

    if verify_kfrag:
        if not isinstance(kfrag, KFrag) or not prepared_capsule.verify_kfrag(kfrag):
            raise KFrag.NotValid

    return CapsuleFrag.from_kfrag(prepared_capsule.capsule, kfrag, metadata)


def _encapsulate(alice_pubkey: UmbralPublicKey,
                 key_length: int = DEM_KEYSIZE) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""

    params = alice_pubkey.params
    g = params.g

    priv_r = CurveBN.gen_rand(params.curve)
    pub_r = priv_r * g  # type: Any

    priv_u = CurveBN.gen_rand(params.curve)
    pub_u = priv_u * g  # type: Any

    h = hash_to_curvebn(pub_r, pub_u, params=params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pubkey.point_key  # type: Any

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)


def _decapsulate_original(private_key: UmbralPrivateKey,
                          capsule: Capsule,
                          key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric key"""

    if not capsule.verify():
        # Check correctness of original ciphertext
        raise capsule.NotValid("Capsule verification failed.")

    shared_key = private_key.bn_key * (capsule.point_e + capsule.point_v)  # type: Any
    key = kdf(shared_key, key_length)
    return key


def _decapsulate_reencrypted(receiving_privkey: UmbralPrivateKey,
                             prepared_capsule: PreparedCapsule,
                             cfrags: Sequence[CapsuleFrag],
                             key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric encapsulated_key"""

    capsule = prepared_capsule.capsule
    params = capsule.params

    pub_key = receiving_privkey.get_pubkey().point_key
    priv_key = receiving_privkey.bn_key

    precursor = cfrags[0].point_precursor
    dh_point = priv_key * precursor

    # Combination of CFrags via Shamir's Secret Sharing reconstruction
    xs = list()
    for cfrag in cfrags:
        x = hash_to_curvebn(precursor,
                            pub_key,
                            dh_point,
                            bytes(constants.X_COORDINATE),
                            cfrag.kfrag_id,
                            params=params)
        xs.append(x)

    e_summands, v_summands = list(), list()
    for cfrag, x in zip(cfrags, xs):
        if precursor != cfrag.point_precursor:
            raise ValueError("Attached CFrags are not pairwise consistent")
        lambda_i = lambda_coeff(x, xs)
        e_summands.append(lambda_i * cfrag.point_e1)
        v_summands.append(lambda_i * cfrag.point_v1)

    e_prime = sum(e_summands[1:], e_summands[0])
    v_prime = sum(v_summands[1:], v_summands[0])

    # Secret value 'd' allows to make Umbral non-interactive
    d = hash_to_curvebn(precursor,
                        pub_key,
                        dh_point,
                        bytes(constants.NON_INTERACTIVE),
                        params=params)

    e, v, s = capsule.components()
    h = hash_to_curvebn(e, v, params=params)

    orig_pub_key = prepared_capsule.delegating_key.point_key

    if not (s / d) * orig_pub_key == (h * e_prime) + v_prime:
        raise GenericUmbralError()

    shared_key = d * (e_prime + v_prime)
    encapsulated_key = kdf(shared_key, key_length)
    return encapsulated_key


def encrypt(alice_pubkey: UmbralPublicKey, plaintext: bytes) -> Tuple[bytes, Capsule]:
    """
    Performs an encryption using the UmbralDEM object and encapsulates a key
    for the sender using the public key provided.

    Returns the ciphertext and the KEM Capsule.
    """
    key, capsule = _encapsulate(alice_pubkey, DEM_KEYSIZE)

    capsule_bytes = bytes(capsule)

    dem = UmbralDEM(key)
    ciphertext = dem.encrypt(plaintext, authenticated_data=capsule_bytes)

    return ciphertext, capsule


def _open_capsule(prepared_capsule: PreparedCapsule,
                  cfrags: Sequence[CapsuleFrag],
                  receiving_privkey: UmbralPrivateKey,
                  check_proof: bool = True) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """

    if check_proof:
        offending_cfrags = []
        for cfrag in cfrags:
            if not prepared_capsule.verify_cfrag(cfrag):
                offending_cfrags.append(cfrag)

        if offending_cfrags:
            error_msg = "Decryption error: Some CFrags are not correct"
            raise UmbralCorrectnessError(error_msg, offending_cfrags)

    key = _decapsulate_reencrypted(receiving_privkey, prepared_capsule, cfrags)
    return key


def decrypt_original(ciphertext: bytes,
                     capsule: Capsule,
                     decrypting_key: UmbralPrivateKey) -> bytes:

    if not isinstance(ciphertext, bytes) or len(ciphertext) < DEM_NONCE_SIZE:
        raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    elif not isinstance(capsule, Capsule) or not capsule.verify():
        raise Capsule.NotValid
    elif not isinstance(decrypting_key, UmbralPrivateKey):
        raise TypeError("The decrypting key is not an UmbralPrivateKey")

    encapsulated_key = _decapsulate_original(decrypting_key, capsule)

    dem = UmbralDEM(encapsulated_key)
    try:
        cleartext = dem.decrypt(ciphertext, authenticated_data=bytes(capsule))
    except InvalidTag as e:
        raise UmbralDecryptionError() from e

    return cleartext


def decrypt_reencrypted(ciphertext: bytes,
                        capsule: PreparedCapsule,
                        cfrags: Sequence[CapsuleFrag],
                        decrypting_key: UmbralPrivateKey,
                        check_proof: bool = True) -> bytes:

    if not isinstance(ciphertext, bytes) or len(ciphertext) < DEM_NONCE_SIZE:
        raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    elif not isinstance(capsule, PreparedCapsule) or not capsule.verify():
        raise Capsule.NotValid
    elif not isinstance(decrypting_key, UmbralPrivateKey):
        raise TypeError("The decrypting key is not an UmbralPrivateKey")

    encapsulated_key = _open_capsule(capsule, cfrags, decrypting_key, check_proof=check_proof)

    dem = UmbralDEM(encapsulated_key)
    try:
        cleartext = dem.decrypt(ciphertext, authenticated_data=bytes(capsule.capsule))
    except InvalidTag as e:
        raise UmbralDecryptionError() from e

    return cleartext
