"""
Copyright (C) 2018 NuCypher

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
from typing import Dict, List, Optional, Tuple, Union, Any

from bytestring_splitter import BytestringSplitter
from umbral._pre import prove_cfrag_correctness
from umbral.config import default_curve
from umbral.curvebn import CurveBN
from umbral.dem import UmbralDEM, DEM_KEYSIZE, DEM_NONCE_SIZE
from umbral.fragments import (KFrag, CapsuleFrag, NO_KEY, DELEGATING_ONLY,
                              RECEIVING_ONLY, DELEGATING_AND_RECEIVING)
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.signing import Signer
from umbral.utils import poly_eval, lambda_coeff, kdf
from umbral.curve import Curve

class GenericUmbralError(Exception):
    pass


class UmbralCorrectnessError(GenericUmbralError):
    def __init__(self, message: str, offending_cfrags: List[CapsuleFrag]) -> None:
        super().__init__(message)
        self.offending_cfrags = offending_cfrags


class Capsule(object):
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

        self._point_e = point_e
        self._point_v = point_v
        self._bn_sig = bn_sig

        self._attached_cfrags = list()    # type: list
        self._cfrag_correctness_keys = {
            'delegating': None, 'receiving': None, 'verifying': None
        }   # type: dict

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

    def _set_cfrag_correctness_key(self, key_type: str, key: Optional[UmbralPublicKey]) -> bool:
        if key_type not in ("delegating", "receiving", "verifying"): 
            raise ValueError("You can only set 'delegating', 'receiving' or 'verifying' keys.") 

        current_key = self._cfrag_correctness_keys[key_type]

        if current_key is None:
            if key is None:
                return False
            elif self.params != key.params:
                raise TypeError("You are trying to set a key with different UmbralParameters.")
            else:
                self._cfrag_correctness_keys[key_type] = key
                return True
        elif key in (None, current_key):
            return False
        else:
            raise ValueError("The {} key is already set; you can't set it again.".format(key_type))

    def get_correctness_keys(self) -> Dict[str, Union[UmbralPublicKey, None]]:
        return dict(self._cfrag_correctness_keys)

    def set_correctness_keys(self,
                             delegating: Optional[UmbralPublicKey] = None,
                             receiving: Optional[UmbralPublicKey] = None,
                             verifying: Optional[UmbralPublicKey] = None,
                             ) -> Tuple[bool, bool, bool]:

        delegating_key_details = self._set_cfrag_correctness_key(key_type="delegating", key=delegating)
        receiving_key_details = self._set_cfrag_correctness_key(key_type="receiving", key=receiving)
        verifying_key_details = self._set_cfrag_correctness_key(key_type="verifying", key=verifying)

        return delegating_key_details, receiving_key_details, verifying_key_details

    def to_bytes(self) -> bytes:
        """
        Serialize the Capsule into a bytestring.
        """
        e, v, s = self.components()
        return e.to_bytes() + v.to_bytes() + s.to_bytes()

    def verify(self) -> bool:

        g = self.params.g
        e, v, s = self.components()

        h = CurveBN.hash(e, v, params=self.params)

        result = s * g == v + (h * e)      # type: bool
        return result

    def attach_cfrag(self, cfrag: CapsuleFrag) -> None:
        if cfrag.verify_correctness(self):
            self._attached_cfrags.append(cfrag)
        else:
            error_msg = "CFrag is not correct and cannot be attached to the Capsule"
            raise UmbralCorrectnessError(error_msg, [cfrag])

    def components(self) -> Tuple[Point, Point, CurveBN]:
        return self._point_e, self._point_v, self._bn_sig

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

    def __len__(self) -> int:
        return len(self._attached_cfrags)

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, hex(int(self._bn_sig))[2:17])


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

    from constant_sorrow import constants

    # Secret value 'd' allows to make Umbral non-interactive
    d = CurveBN.hash(precursor,
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
        share_index = CurveBN.hash(precursor,
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


def reencrypt(kfrag: KFrag, capsule: Capsule, provide_proof: bool = True, 
              metadata: Optional[bytes] = None) -> CapsuleFrag:

    if not isinstance(capsule, Capsule) or not capsule.verify():
        raise Capsule.NotValid
    elif not isinstance(kfrag, KFrag) or not kfrag.verify_for_capsule(capsule):
        raise KFrag.NotValid

    rk = kfrag._bn_key
    e1 = rk * capsule._point_e  # type: Any
    v1 = rk * capsule._point_v  # type: Any

    cfrag = CapsuleFrag(point_e1=e1, point_v1=v1, kfrag_id=kfrag.id,
                        point_precursor=kfrag._point_precursor)

    if provide_proof:
        prove_cfrag_correctness(cfrag, kfrag, capsule, metadata)

    return cfrag


def _encapsulate(alice_pubkey: UmbralPublicKey, 
                 key_length: int = DEM_KEYSIZE) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""

    params = alice_pubkey.params
    g = params.g

    priv_r = CurveBN.gen_rand(params.curve)
    pub_r = priv_r * g  # type: Any

    priv_u = CurveBN.gen_rand(params.curve)
    pub_u = priv_u * g  # type: Any

    h = CurveBN.hash(pub_r, pub_u, params=params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pubkey.point_key  # type: Any

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)


def _decapsulate_original(priv_key: UmbralPrivateKey,
                          capsule: Capsule,
                          key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric key"""

    if not capsule.verify():
        # Check correctness of original ciphertext
        raise capsule.NotValid("Capsule verification failed.")

    shared_key = priv_key.bn_key * (capsule._point_e + capsule._point_v)  # type: Any
    key = kdf(shared_key, key_length)
    return key


def _decapsulate_reencrypted(receiving_privkey: UmbralPrivateKey, capsule: Capsule,
                             key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric encapsulated_key"""

    params = capsule.params

    pub_key = receiving_privkey.get_pubkey().point_key
    priv_key = receiving_privkey.bn_key

    precursor = capsule._attached_cfrags[0]._point_precursor
    dh_point = priv_key * precursor

    from constant_sorrow import constants

    # Combination of CFrags via Shamir's Secret Sharing reconstruction
    if len(capsule._attached_cfrags) > 1:
        xs = [CurveBN.hash(precursor,
                           pub_key,
                           dh_point,
                           bytes(constants.X_COORDINATE),
                           cfrag._kfrag_id,
                           params=params)
              for cfrag in capsule._attached_cfrags]

        e_summands, v_summands = list(), list()
        for cfrag, x in zip(capsule._attached_cfrags, xs):
            if precursor != cfrag._point_precursor:
                raise ValueError("Attached CFrags are not pairwise consistent")

            lambda_i = lambda_coeff(x, xs)
            e_summands.append(lambda_i * cfrag._point_e1)
            v_summands.append(lambda_i * cfrag._point_v1)

        e_prime = sum(e_summands[1:], e_summands[0])
        v_prime = sum(v_summands[1:], v_summands[0])
    else:
        e_prime = capsule._attached_cfrags[0]._point_e1
        v_prime = capsule._attached_cfrags[0]._point_v1

    # Secret value 'd' allows to make Umbral non-interactive
    d = CurveBN.hash(precursor,
                     pub_key,
                     dh_point,
                     bytes(constants.NON_INTERACTIVE),
                     params=params)

    e, v, s = capsule.components()
    h = CurveBN.hash(e, v, params=params)

    orig_pub_key = capsule.get_correctness_keys()['delegating'].point_key  # type: ignore

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


def _open_capsule(capsule: Capsule, receiving_privkey: UmbralPrivateKey,
                  check_proof: bool = True) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """

    if check_proof:
        offending_cfrags = []
        for cfrag in capsule._attached_cfrags:
            if not cfrag.verify_correctness(capsule):
                offending_cfrags.append(cfrag)

        if offending_cfrags:
            error_msg = "Decryption error: Some CFrags are not correct"
            raise UmbralCorrectnessError(error_msg, offending_cfrags)

    key = _decapsulate_reencrypted(receiving_privkey, capsule)
    return key


def decrypt(ciphertext: bytes, capsule: Capsule, decrypting_key: UmbralPrivateKey,
            check_proof: bool = True) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """

    if not isinstance(ciphertext, bytes) or len(ciphertext) < DEM_NONCE_SIZE:
        raise ValueError("Input ciphertext must be a bytes object of length >= {}".format(DEM_NONCE_SIZE))
    elif not isinstance(capsule, Capsule) or not capsule.verify():
        raise Capsule.NotValid
    elif not isinstance(decrypting_key, UmbralPrivateKey):
        raise TypeError("The decrypting key is not an UmbralPrivateKey")

    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        # (i.e., this is a re-encrypted capsule)
        encapsulated_key = _open_capsule(capsule, decrypting_key, check_proof=check_proof)
    else:
        # Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        # (i.e., this is an original capsule)
        encapsulated_key = _decapsulate_original(decrypting_key, capsule)

    dem = UmbralDEM(encapsulated_key)
    cleartext = dem.decrypt(ciphertext, authenticated_data=bytes(capsule))
    return cleartext
