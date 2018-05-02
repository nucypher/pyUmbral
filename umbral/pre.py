import hmac

import os
from typing import Tuple, Union, List

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from umbral.curvebn import CurveBN
from umbral.config import default_params, default_curve
from umbral.dem import UmbralDEM
from umbral.fragments import KFrag, CapsuleFrag, CorrectnessProof
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.utils import poly_eval, lambda_coeff, kdf, get_curve_keysize_bytes

from io import BytesIO


CHACHA20_KEY_SIZE = 32


class GenericUmbralError(Exception):
    pass


class UmbralCorrectnessError(GenericUmbralError):
    def __init__(self, message, offending_cfrags):
        super().__init__(message)
        self.offending_cfrags = offending_cfrags


class Capsule(object):
    def __init__(self,
                 point_e=None,
                 point_v=None,
                 bn_sig=None,
                 point_e_prime=None,
                 point_v_prime=None,
                 point_noninteractive=None):

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

        self._point_e = point_e
        self._point_v = point_v
        self._bn_sig = bn_sig

        self._point_e_prime = point_e_prime
        self._point_v_prime = point_v_prime
        self._point_noninteractive = point_noninteractive

        self._attached_cfrags = list()

    class NotValid(ValueError):
        """
        raised if the capsule does not pass verification.
        """

    @classmethod
    def from_bytes(cls, capsule_bytes: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiates a Capsule object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        capsule_buff = BytesIO(capsule_bytes)

        # CurveBNs are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        if len(capsule_bytes) == 197:
            e = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            v = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            sig = CurveBN.from_bytes(capsule_buff.read(key_size), curve)
            e_prime = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            v_prime = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            ni = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
        else:
            e = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            v = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            sig = CurveBN.from_bytes(capsule_buff.read(key_size), curve)
            e_prime = v_prime = ni = None

        return cls(point_e=e, point_v=v, bn_sig=sig,
                   point_e_prime=e_prime, point_v_prime=v_prime, 
                   point_noninteractive=ni)

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

    def verify(self, params: UmbralParameters=None) -> bool:
        params = params if params is not None else default_params()

        e = self._point_e
        v = self._point_v
        s = self._bn_sig
        h = CurveBN.hash_to_bn(e, v, params=params)

        return s * params.g == v + (h * e)

    def attach_cfrag(self, cfrag: CapsuleFrag) -> None:
        self._attached_cfrags.append(cfrag)

    def original_components(self) -> Tuple[Point, Point, CurveBN]:
        return self._point_e, self._point_v, self._bn_sig

    def activated_components(self) -> Union[Tuple[None, None, None], Tuple[Point, Point, Point]]:
        return self._point_e_prime, self._point_v_prime, self._point_noninteractive

    def _reconstruct_shamirs_secret(self, 
                                    pub_a: Union[UmbralPublicKey, Point], 
                                    priv_b: Union[UmbralPrivateKey, CurveBN],
                                    params: UmbralParameters=None) -> None:

        params = params if params is not None else default_params()

        if isinstance(priv_b, UmbralPrivateKey):
            priv_b = priv_b.bn_key

        if isinstance(pub_a, UmbralPublicKey):
            pub_a = pub_a.point_key

        g = params.g
        pub_b = priv_b * g
        g_ab = priv_b * pub_a

        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        blake2b.update(pub_a.to_bytes())
        blake2b.update(pub_b.to_bytes())
        blake2b.update(g_ab.to_bytes())
        hashed_dh_tuple = blake2b.finalize()

        cfrag_0 = self._attached_cfrags[0]
        id_0 = cfrag_0._kfrag_id
        x_0 = CurveBN.hash_to_bn(id_0, hashed_dh_tuple, params=params)
        if len(self._attached_cfrags) > 1:
            xs = [CurveBN.hash_to_bn(cfrag._kfrag_id, hashed_dh_tuple, params=params)
                    for cfrag in self._attached_cfrags]
            lambda_0 = lambda_coeff(x_0, xs)
            e = lambda_0 * cfrag_0._point_e1
            v = lambda_0 * cfrag_0._point_v1

            for cfrag in self._attached_cfrags[1:]:
                x_i = CurveBN.hash_to_bn(cfrag._kfrag_id, hashed_dh_tuple, params=params)
                lambda_i = lambda_coeff(x_i, xs)
                e = e + (lambda_i * cfrag._point_e1)
                v = v + (lambda_i * cfrag._point_v1)
        else:
            e = cfrag_0._point_e1
            v = cfrag_0._point_v1

        self._point_e_prime = e
        self._point_v_prime = v
        self._point_noninteractive = cfrag_0._point_noninteractive

    def __bytes__(self):
        return self.to_bytes()

    def __eq__(self, other):
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
            # (dormat) Capsules.  Then an attacker can, by alternating between activated and dormant
            # Capsules, determine if a given Capsule is activated.  Do we care about this?
            # Again, it's hard to imagine why.
            return False

    def __hash__(self):
        # We only ever want to store in a hash table based on original components;
        # A Capsule that is part of a dict needs to continue to be lookup-able even
        # after activation.
        # Note: In case this isn't obvious, don't use this as a secure hash.  Use BLAKE2b or something.
        component_bytes = tuple(component.to_bytes() for component in self.original_components())
        return hash(component_bytes)


def split_rekey(priv_a: Union[UmbralPrivateKey, CurveBN],
                pub_b: Union[UmbralPublicKey, Point],
                threshold: int, N: int,
                params: UmbralParameters=None) -> List[KFrag]:
    """
    Creates a re-encryption key from Alice to Bob and splits it in KFrags,
    using Shamir's Secret Sharing. Requires a threshold number of KFrags 
    out of N to guarantee correctness of re-encryption.

    Returns a list of KFrags.
    """
    params = params if params is not None else default_params()

    if isinstance(priv_a, UmbralPrivateKey):
        priv_a = priv_a.bn_key

    if isinstance(pub_b, UmbralPublicKey):
        pub_b = pub_b.point_key

    g = params.g
    pub_a = priv_a * g

    x = CurveBN.gen_rand(params.curve)
    xcomp = x * g
    d = CurveBN.hash_to_bn(xcomp, pub_b, pub_b * x, params=params)

    coeffs = [priv_a * (~d)]
    coeffs += [CurveBN.gen_rand(params.curve) for _ in range(threshold - 1)]

    u = params.u

    g_ab = priv_a * pub_b

    blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
    blake2b.update(pub_a.to_bytes())
    blake2b.update(pub_b.to_bytes())
    blake2b.update(g_ab.to_bytes())
    hashed_dh_tuple = blake2b.finalize()

    kfrags = []

    bn_size = CurveBN.get_size(params.curve)
    
    for _ in range(N):
        id_kfrag = os.urandom(bn_size)

        share_x = CurveBN.hash_to_bn(id_kfrag, hashed_dh_tuple, params=params)

        rk = poly_eval(coeffs, share_x)

        u1 = rk * u
        y = CurveBN.gen_rand(params.curve)

        z1 = CurveBN.hash_to_bn(y * g, id_kfrag, pub_a, pub_b, u1, xcomp, params=params)
        z2 = y - priv_a * z1

        kfrag = KFrag(id=id_kfrag, bn_key=rk, 
                      point_noninteractive=xcomp, point_commitment=u1, 
                      bn_sig1=z1, bn_sig2=z2)
        kfrags.append(kfrag)

    return kfrags


def reencrypt(kfrag: KFrag, capsule: Capsule, params: UmbralParameters=None, 
              provide_proof=True, metadata: bytes=None) -> CapsuleFrag:
    if params is None:
        params = default_params()

    if not capsule.verify(params):
        raise capsule.NotValid

    e1 = kfrag._bn_key * capsule._point_e
    v1 = kfrag._bn_key * capsule._point_v

    cfrag = CapsuleFrag(point_e1=e1, point_v1=v1, kfrag_id=kfrag._id, 
                        point_noninteractive=kfrag._point_noninteractive)

    if provide_proof:
        _prove_correctness(cfrag, kfrag, capsule, metadata, params)

    return cfrag


def _prove_correctness(cfrag: CapsuleFrag, kfrag: KFrag, capsule: Capsule, 
                       metadata: bytes=None, params: UmbralParameters=None
                      ) -> CorrectnessProof:
    params = params if params is not None else default_params()

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    e = capsule._point_e
    v = capsule._point_v

    u = params.u
    u1 = kfrag._point_commitment

    rk = kfrag._bn_key

    t = CurveBN.gen_rand(params.curve)
    e2 = t * e
    v2 = t * v
    u2 = t * u

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]

    if metadata is not None:
        hash_input.append(metadata)

    h = CurveBN.hash_to_bn(*hash_input, params=params)

    z3 = t + h * rk

    cfrag.proof = CorrectnessProof(point_e2=e2, 
                                   point_v2=v2, 
                                   point_kfrag_commitment=u1,
                                   point_kfrag_pok=u2,
                                   bn_kfrag_sig1=kfrag._bn_sig1,
                                   bn_kfrag_sig2=kfrag._bn_sig2,
                                   bn_sig=z3,
                                   metadata=metadata)

    # Check correctness of original ciphertext (check nº 2) at the end
    # to avoid timing oracles
    if not capsule.verify(params):
        raise capsule.NotValid("Capsule verification failed.")

def _verify_correctness(capsule: Capsule, cfrag: CapsuleFrag,
                    pub_a: Point, pub_b: Point, 
                    params: UmbralParameters=None) -> bool:
    
    
    proof = cfrag.proof

    params = params if params is not None else default_params()

    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1
    xcomp = cfrag._point_noninteractive
    kfrag_id = cfrag._kfrag_id

    e2 = proof._point_e2
    v2 = proof._point_v2

    g = params.g
    u = params.u

    u1 = proof._point_kfrag_commitment
    u2 = proof._point_kfrag_pok

    z1 = proof._bn_kfrag_sig1
    z2 = proof._bn_kfrag_sig2
    z3 = proof._bn_sig

    g_y = (z2 * g) + (z1 * pub_a)

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if proof.metadata is not None:
        hash_input.append(proof.metadata)
    
    h = CurveBN.hash_to_bn(*hash_input, params=params)

    signature_input = [g_y, kfrag_id, pub_a, pub_b, u1, xcomp]
    kfrag_signature1 = CurveBN.hash_to_bn(*signature_input, params=params)
    valid_kfrag_signature = z1 == kfrag_signature1
    
    correct_reencryption_of_e = z3 * e == e2 + (h * e1)
    
    correct_reencryption_of_v = z3 * v == v2 + (h * v1)

    correct_rk_commitment = z3 * u == u2 + (h * u1)
    
    return valid_kfrag_signature        \
         & correct_reencryption_of_e    \
         & correct_reencryption_of_v    \
         & correct_rk_commitment

def _encapsulate(alice_pub_key: Point, key_length=32,
                 params: UmbralParameters=None) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""
    params = params if params is not None else default_params()

    g = params.g

    priv_r = CurveBN.gen_rand(params.curve)
    pub_r = priv_r * g

    priv_u = CurveBN.gen_rand(params.curve)
    pub_u = priv_u * g

    h = CurveBN.hash_to_bn(pub_r, pub_u, params=params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pub_key

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s)


def _decapsulate_original(priv_key: CurveBN, capsule: Capsule, key_length=32,
                          params: UmbralParameters=None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    shared_key = priv_key * (capsule._point_e+capsule._point_v)
    key = kdf(shared_key, key_length)

    if not capsule.verify(params):
        # Check correctness of original ciphertext
        # (check nº 2) at the end to avoid timing oracles
        raise capsule.NotValid("Capsule verification failed.")

    return key


def _decapsulate_reencrypted(pub_key: Point, priv_key: CurveBN,
                            orig_pub_key: Point, capsule: Capsule,
                            key_length=32, params: UmbralParameters=None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    xcomp = capsule._point_noninteractive
    d = CurveBN.hash_to_bn(xcomp, pub_key, priv_key * xcomp, params=params)

    e_prime = capsule._point_e_prime
    v_prime = capsule._point_v_prime

    shared_key = d * (e_prime + v_prime)

    key = kdf(shared_key, key_length)

    e = capsule._point_e
    v = capsule._point_v
    s = capsule._bn_sig
    h = CurveBN.hash_to_bn(e, v, params=params)
    inv_d = ~d

    if not (s*inv_d) * orig_pub_key == (h*e_prime) + v_prime:
        raise GenericUmbralError()
    return key


def encrypt(alice_pubkey: UmbralPublicKey, plaintext: bytes,
            params: UmbralParameters=None) -> Tuple[bytes, Capsule]:
    """
    Performs an encryption using the UmbralDEM object and encapsulates a key
    for the sender using the public key provided.

    Returns the ciphertext and the KEM Capsule.
    """
    params = params if params is not None else default_params()

    key, capsule = _encapsulate(alice_pubkey.point_key, CHACHA20_KEY_SIZE, params=params)

    capsule_bytes = bytes(capsule)

    dem = UmbralDEM(key)
    ciphertext = dem.encrypt(plaintext, authenticated_data=capsule_bytes)

    return ciphertext, capsule


def _open_capsule(capsule: Capsule, bob_privkey: UmbralPrivateKey,
                  alice_pubkey: UmbralPublicKey, params: UmbralParameters=None, 
                  check_proof=True) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """
    params = params if params is not None else default_params()

    priv_b = bob_privkey.bn_key
    pub_b = bob_privkey.get_pubkey().point_key

    pub_a = alice_pubkey.point_key

    # TODO: Change dict for a list if issue #116 goes through
    if check_proof:
        offending_cfrags = []
        for cfrag in capsule._attached_cfrags:
            if not _verify_correctness(capsule, cfrag, pub_a, pub_b, params):
                offending_cfrags.append(cfrag)

        if offending_cfrags:
            error_msg = "Decryption error: Some CFrags are not correct"
            raise UmbralCorrectnessError(error_msg, offending_cfrags)

    capsule._reconstruct_shamirs_secret(pub_a, priv_b, params=params)

    key = _decapsulate_reencrypted(pub_b, priv_b, pub_a, capsule, params=params)
    return key


def decrypt(ciphertext: bytes, capsule: Capsule, 
            priv_key: UmbralPrivateKey, alice_pub_key: UmbralPublicKey=None, 
            params: UmbralParameters=None, check_proof=True) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    params = params if params is not None else default_params()

    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        # (i.e., this is a re-encrypted capsule)
        
        bob_priv_key = priv_key

        encapsulated_key = _open_capsule(capsule, bob_priv_key, alice_pub_key, 
                                         params=params, check_proof=check_proof)
        dem = UmbralDEM(encapsulated_key)

        original_capsule_bytes = capsule._original_to_bytes()
        cleartext = dem.decrypt(ciphertext, authenticated_data=original_capsule_bytes)
    else:
        # Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        # (i.e., this is an original capsule)
        encapsulated_key = _decapsulate_original(priv_key.bn_key, capsule, params=params)
        dem = UmbralDEM(encapsulated_key)

        capsule_bytes = bytes(capsule)
        cleartext = dem.decrypt(ciphertext, authenticated_data=capsule_bytes)

    return cleartext
