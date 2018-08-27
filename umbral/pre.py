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
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve

from bytestring_splitter import BytestringSplitter
from umbral._pre import prove_cfrag_correctness
from umbral.config import default_curve
from umbral.curvebn import CurveBN
from umbral.dem import UmbralDEM, DEM_KEYSIZE
from umbral.fragments import KFrag, CapsuleFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.signing import Signer
from umbral.utils import poly_eval, lambda_coeff, kdf


class GenericUmbralError(Exception):
    pass


class UmbralCorrectnessError(GenericUmbralError):
    def __init__(self, message: str, offending_cfrags: List[CapsuleFrag]) -> None:
        super().__init__(message)
        self.offending_cfrags = offending_cfrags


class Capsule(object):
    def __init__(self,
                 params: UmbralParameters,
                 point_e: Optional[Point] = None,
                 point_v: Optional[Point] = None,
                 bn_sig: Optional[CurveBN] = None,
                 point_e_prime: Optional[Point] = None,
                 point_v_prime: Optional[Point] = None,
                 point_noninteractive: Optional[Point] = None,
                 delegating_pubkey: Optional[UmbralPublicKey] = None,
                 receiving_pubkey: Optional[UmbralPublicKey] = None,
                 verifying_pubkey: None = None
                 ) -> None:

        self._umbral_params = params

        if isinstance(point_e, Point):
            if not isinstance(point_v, Point) or not isinstance(bn_sig, CurveBN):
                raise TypeError("Need point_e, point_v, and bn_sig to make a Capsule.")
        elif isinstance(point_e_prime, Point):
            if not isinstance(point_v_prime, Point) or not isinstance(point_noninteractive, Point):
                raise TypeError("Need e_prime, v_prime, and point_noninteractive to make an activated Capsule.")
        else:
            raise TypeError(
                "Need proper Points and/or CurveBNs to make a Capsule.  Pass either Alice's data or Bob's. " \
                "Passing both is also fine.")

        self._cfrag_correctness_keys = {"delegating": delegating_pubkey,
                                        "receiving": receiving_pubkey,
                                        "verifying": verifying_pubkey}

        self._point_e = point_e
        self._point_v = point_v
        self._bn_sig = bn_sig

        self._point_e_prime = point_e_prime
        self._point_v_prime = point_v_prime
        self._point_noninteractive = point_noninteractive

        self._attached_cfrags = list()    # type: list

    @classmethod
    def expected_bytes_length(cls, curve: Optional[EllipticCurve] = None, activated: bool = False) -> int:
        """
        Returns the size (in bytes) of a Capsule given the curve.
        If no curve is provided, it will use the default curve.
        """
        curve = curve if curve is not None else default_curve()
        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        if not activated:
            return (bn_size * 1) + (point_size * 2)
        else:
            return (bn_size * 1) + (point_size * 5)

    class NotValid(ValueError):
        """
        raised if the capsule does not pass verification.
        """

    @classmethod
    def from_bytes(cls, capsule_bytes: bytes, params: UmbralParameters) -> 'Capsule':
        """
        Instantiates a Capsule object from the serialized data.
        """
        curve = params.curve

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        capsule_bytes_length = len(capsule_bytes)
        expected_len_original = cls.expected_bytes_length(curve, activated=False)
        expected_len_activated = cls.expected_bytes_length(curve, activated=True)
        arguments = {'curve': curve}
        if capsule_bytes_length == expected_len_original:
            splitter = BytestringSplitter(
                (Point, point_size, arguments),  # point_e
                (Point, point_size, arguments),  # point_v
                (CurveBN, bn_size, arguments)  # bn_sig
            )
        elif capsule_bytes_length == expected_len_activated:
            splitter = BytestringSplitter(
                (Point, point_size, arguments),  # point_e
                (Point, point_size, arguments),  # point_v
                (CurveBN, bn_size, arguments),  # bn_sig
                (Point, point_size, arguments),  # point_e_prime
                (Point, point_size, arguments),  # point_v_prime
                (Point, point_size, arguments)  # point_noninteractive
            )
        else:
            raise ValueError("Byte string does not have a valid length for a Capsule")

        components = splitter(capsule_bytes)
        return cls(params, *components)

    def _set_cfrag_correctness_key(self, key_type: str, key: UmbralPublicKey) -> bool:
        if key_type not in ("delegating", "receiving", "verifying"): 
            raise ValueError("You can only set 'delegating', 'receiving' or 'verifying' keys.") 

        current_key = self._cfrag_correctness_keys[key_type]

        if current_key is None:
            if key is None:
                raise TypeError("The {} key is not set and you didn't pass one.".format(key_type))
            elif self._umbral_params != key.params:
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

    @typing.no_type_check
    def _original_to_bytes(self) -> bytes:
        return bytes().join(c.to_bytes() for c in self.original_components())

    def to_bytes(self) -> bytes:
        """
        Serialize the Capsule into a bytestring.
        """
        bytes_representation = self._original_to_bytes()
        if all(self.activated_components()):
            bytes_representation += bytes().join(c.to_bytes() for c in self.activated_components())
        return bytes_representation

    def verify(self) -> bool:

        g = self._umbral_params.g
        e = self._point_e
        v = self._point_v
        s = self._bn_sig
        h = CurveBN.hash(e, v, params=self._umbral_params)

        result = s * g == v + (h * e)      # type: bool
        return result

    def attach_cfrag(self, cfrag: CapsuleFrag) -> None:
        if cfrag.verify_correctness(self):
            self._attached_cfrags.append(cfrag)
        else:
            error_msg = "CFrag is not correct and cannot be attached to the Capsule"
            raise UmbralCorrectnessError(error_msg, [cfrag])

    def original_components(self) -> Tuple[Point, Point, CurveBN]:
        return self._point_e, self._point_v, self._bn_sig

    def activated_components(self) -> Union[Tuple[None, None, None], Tuple[Point, Point, Point]]:
        return self._point_e_prime, self._point_v_prime, self._point_noninteractive

    def _reconstruct_shamirs_secret(self, priv_b: UmbralPrivateKey) -> None:
        params = self._umbral_params
        g = params.g

        pub_b = priv_b.get_pubkey()
        priv_b = priv_b.bn_key

        cfrag_0 = self._attached_cfrags[0]
        id_0 = cfrag_0._kfrag_id
        ni = cfrag_0._point_noninteractive
        xcoord = cfrag_0._point_xcoord

        dh_xcoord = priv_b * xcoord

        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        blake2b.update(xcoord.to_bytes())
        blake2b.update(pub_b.to_bytes())
        blake2b.update(dh_xcoord.to_bytes())
        hashed_dh_tuple = blake2b.finalize()

        if len(self._attached_cfrags) > 1:
            xs = [CurveBN.hash(cfrag._kfrag_id, hashed_dh_tuple, params=params)
                  for cfrag in self._attached_cfrags]
            x_0 = CurveBN.hash(id_0, hashed_dh_tuple, params=params)
            lambda_0 = lambda_coeff(x_0, xs)
            e = lambda_0 * cfrag_0._point_e1
            v = lambda_0 * cfrag_0._point_v1

            for cfrag in self._attached_cfrags[1:]:
                if (ni, xcoord) != (cfrag._point_noninteractive, cfrag._point_xcoord):
                    raise ValueError("Attached CFrags are not pairwise consistent")

                x_i = CurveBN.hash(cfrag._kfrag_id, hashed_dh_tuple, params=params)
                lambda_i = lambda_coeff(x_i, xs)
                e = e + (lambda_i * cfrag._point_e1)
                v = v + (lambda_i * cfrag._point_v1)
        else:
            e = cfrag_0._point_e1
            v = cfrag_0._point_v1

        self._point_e_prime = e
        self._point_v_prime = v
        self._point_noninteractive = ni

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __eq__(self, other: 'Capsule') -> bool:
        """
        If both Capsules are activated, we compare only the activated components.
        Otherwise, we compare only original components.
        Each component is compared to its counterpart in constant time per the __eq__ of Point and CurveBN.
        """
        if all(self.activated_components() + other.activated_components()):
            activated_match = self.activated_components() == other.activated_components()
            return activated_match
        elif all(self.original_components() + other.original_components()):
            original_match = self.original_components() == other.original_components()
            return original_match
        else:
            # This is not constant time obviously, but it's hard to imagine how this is valuable as
            # an attacker already knows about her own Capsule.  It's possible that a Bob, having
            # activated a Capsule, will make it available for comparison via an API amidst other
            # (dormant) Capsules.  Then an attacker can, by alternating between activated and dormant
            # Capsules, determine if a given Capsule is activated.  Do we care about this?
            # Again, it's hard to imagine why.
            return False

    @typing.no_type_check
    def __hash__(self) -> int:
        # We only ever want to store in a hash table based on original components;
        # A Capsule that is part of a dict needs to continue to be lookup-able even
        # after activation.
        # Note: In case this isn't obvious, don't use this as a secure hash.  Use BLAKE2b or something.
        component_bytes = tuple(component.to_bytes() for component in self.original_components())
        return hash(component_bytes)

    def __len__(self) -> int:
        return len(self._attached_cfrags)

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, hex(int(self._bn_sig))[2:17])

def split_rekey(delegating_privkey: UmbralPrivateKey, signer: Signer,
                receiving_pubkey: UmbralPublicKey,
                threshold: int, N: int) -> List[KFrag]:
    """
    Creates a re-encryption key from Alice to Bob and splits it in KFrags,
    using Shamir's Secret Sharing. Requires a threshold number of KFrags
    out of N to guarantee correctness of re-encryption.

    Returns a list of KFrags.
    """

    if threshold <= 0 or threshold > N:
        raise ValueError('Arguments threshold and N must satisfy 0 < threshold <= N')

    if delegating_privkey.params != receiving_pubkey.params:
        raise ValueError("Keys must have the same parameter set.")

    params = delegating_privkey.params

    g = params.g

    pubkey_a_point = delegating_privkey.get_pubkey().point_key
    privkey_a_bn = delegating_privkey.bn_key

    pubkey_b_point = receiving_pubkey.point_key

    # 'ni' stands for 'Non Interactive'.
    # This point is used as an ephemeral public key in a DH key exchange,
    # and the resulting shared secret 'd' allows to make Umbral non-interactive
    priv_ni = CurveBN.gen_rand(params.curve)
    ni = priv_ni * g
    d = CurveBN.hash(ni, pubkey_b_point, pubkey_b_point * priv_ni, params=params)

    coeffs = [privkey_a_bn * (~d)]
    coeffs += [CurveBN.gen_rand(params.curve) for _ in range(threshold - 1)]

    u = params.u

    # 'xcoord' stands for 'X coordinate'.
    # This point is used as an ephemeral public key in a DH key exchange,
    # and the resulting shared secret 'dh_xcoord' contributes to prevent
    # reconstruction of the re-encryption key without Bob's intervention
    priv_xcoord = CurveBN.gen_rand(params.curve)
    xcoord = priv_xcoord * g

    dh_xcoord = priv_xcoord * pubkey_b_point

    blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
    blake2b.update(xcoord.to_bytes())
    blake2b.update(pubkey_b_point.to_bytes())
    blake2b.update(dh_xcoord.to_bytes())
    hashed_dh_tuple = blake2b.finalize()

    bn_size = CurveBN.expected_bytes_length(params.curve)

    kfrags = []
    for _ in range(N):
        id = os.urandom(bn_size)

        share_x = CurveBN.hash(id, hashed_dh_tuple, params=params)

        rk = poly_eval(coeffs, share_x)

        u1 = rk * u

        kfrag_validity_message = bytes().join(
            bytes(material) for material in (id, pubkey_a_point, pubkey_b_point, u1, ni, xcoord))
        signature = signer(kfrag_validity_message)

        kfrag = KFrag(id=id,
                      bn_key=rk,
                      point_noninteractive=ni,
                      point_commitment=u1,
                      point_xcoord=xcoord,
                      signature=signature)

        kfrags.append(kfrag)

    return kfrags


def reencrypt(kfrag: KFrag, capsule: Capsule, provide_proof: bool = True, 
              metadata: Optional[bytes] = None) -> CapsuleFrag:

    if not capsule.verify():
        raise Capsule.NotValid

    if not kfrag.verify_for_capsule(capsule):
        raise KFrag.NotValid

    rk = kfrag._bn_key
    e1 = rk * capsule._point_e
    v1 = rk * capsule._point_v

    cfrag = CapsuleFrag(point_e1=e1, point_v1=v1, kfrag_id=kfrag._id,
                        point_noninteractive=kfrag._point_noninteractive,
                        point_xcoord=kfrag._point_xcoord)

    if provide_proof:
        prove_cfrag_correctness(cfrag, kfrag, capsule, metadata)

    return cfrag


def _encapsulate(alice_pubkey: UmbralPublicKey, 
                 key_length: int = DEM_KEYSIZE) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""

    params = alice_pubkey.params
    g = params.g

    priv_r = CurveBN.gen_rand(params.curve)
    pub_r = priv_r * g

    priv_u = CurveBN.gen_rand(params.curve)
    pub_u = priv_u * g

    h = CurveBN.hash(pub_r, pub_u, params=params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pubkey.point_key

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)


def _decapsulate_original(priv_key: UmbralPrivateKey, capsule: Capsule, 
                          key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric key"""

    priv_key = priv_key.bn_key

    shared_key = priv_key * (capsule._point_e + capsule._point_v)
    key = kdf(shared_key, key_length)

    if not capsule.verify():
        # Check correctness of original ciphertext
        # (check nº 2) at the end to avoid timing oracles
        raise capsule.NotValid("Capsule verification failed.")

    return key


def _decapsulate_reencrypted(receiving_privkey: UmbralPrivateKey, capsule: Capsule,
                             key_length: int = DEM_KEYSIZE) -> bytes:
    """Derive the same symmetric key"""
    params = capsule._umbral_params

    pub_key = receiving_privkey.get_pubkey().point_key
    priv_key = receiving_privkey.bn_key

    ni = capsule._point_noninteractive
    d = CurveBN.hash(ni, pub_key, priv_key * ni, params=params)

    e_prime = capsule._point_e_prime
    v_prime = capsule._point_v_prime

    shared_key = d * (e_prime + v_prime)

    key = kdf(shared_key, key_length)

    e = capsule._point_e
    v = capsule._point_v
    s = capsule._bn_sig
    h = CurveBN.hash(e, v, params=params)
    inv_d = ~d
    orig_pub_key = capsule.get_correctness_keys()['delegating'].point_key

    if not (s * inv_d) * orig_pub_key == (h * e_prime) + v_prime:
        raise GenericUmbralError()
    return key


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

    receiving_pubkey = receiving_privkey.get_pubkey()

    if check_proof:
        offending_cfrags = []
        for cfrag in capsule._attached_cfrags:
            if not cfrag.verify_correctness(capsule):
                offending_cfrags.append(cfrag)

        if offending_cfrags:
            error_msg = "Decryption error: Some CFrags are not correct"
            raise UmbralCorrectnessError(error_msg, offending_cfrags)

    capsule._reconstruct_shamirs_secret(receiving_privkey)

    key = _decapsulate_reencrypted(receiving_privkey, capsule)
    return key


def decrypt(ciphertext: bytes, capsule: Capsule, decrypting_key: UmbralPrivateKey,
            check_proof: bool = True) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """

    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        # (i.e., this is a re-encrypted capsule)

        encapsulated_key = _open_capsule(capsule, decrypting_key, check_proof=check_proof)
        dem = UmbralDEM(encapsulated_key)

        original_capsule_bytes = capsule._original_to_bytes()
        cleartext = dem.decrypt(ciphertext, authenticated_data=original_capsule_bytes)
    else:
        # Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        # (i.e., this is an original capsule)
        decapsulated_key = _decapsulate_original(decrypting_key, capsule)
        dem = UmbralDEM(decapsulated_key)

        capsule_bytes = bytes(capsule)
        cleartext = dem.decrypt(ciphertext, authenticated_data=capsule_bytes)

    return cleartext
