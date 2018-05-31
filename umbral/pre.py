from typing import Tuple, Union, List

from bytestring_splitter import BytestringSplitter
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from umbral._pre import prove_cfrag_correctness, assess_cfrag_correctness
from umbral.curvebn import CurveBN
from umbral.config import default_params, default_curve
from umbral.dem import UmbralDEM
from umbral.fragments import KFrag, CapsuleFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.signing import Signer
from umbral.utils import poly_eval, lambda_coeff, kdf
import os

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
                 point_noninteractive=None,
                 delegating_pubkey: UmbralPublicKey = None,
                 receiving_pubkey: UmbralPublicKey = None,
                 verifying_pubkey: UmbralPublicKey = None,
                 params: UmbralParameters = None):

        self._umbral_params = params if params is not None else default_params()

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

        self._attached_cfrags = list()

    @classmethod
    def expected_bytes_length(cls, curve: ec.EllipticCurve = None, activated=False):
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
    def from_bytes(cls, capsule_bytes: bytes, params: UmbralParameters = None):
        """
        Instantiates a Capsule object from the serialized data.
        """
        params = params if params is not None else default_params()
        curve = params.curve

        bn_size = CurveBN.expected_bytes_length(curve)
        point_size = Point.expected_bytes_length(curve)

        capsule_bytes_length = len(capsule_bytes)
        if capsule_bytes_length == cls.expected_bytes_length(curve, activated=True):
            splitter = BytestringSplitter(
                (Point, point_size),  # point_e
                (Point, point_size),  # point_v
                (CurveBN, bn_size),  # bn_sig
                (Point, point_size),  # point_e_prime
                (Point, point_size),  # point_v_prime
                (Point, point_size)  # point_noninteractive
            )
        elif capsule_bytes_length == cls.expected_bytes_length(curve, activated=False):
            splitter = BytestringSplitter(
                (Point, point_size),  # point_e
                (Point, point_size),  # point_v
                (CurveBN, bn_size)  # bn_sig
            )
        else:
            raise ValueError("Byte string does not have a valid length for a Capsule")

        components = splitter(capsule_bytes)
        return cls(*components, params=params)

    def _set_cfrag_correctness_key(self, key_type, key: UmbralPublicKey):
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

    def set_correctness_keys(self,
                 delegating: UmbralPublicKey = None,
                 receiving: UmbralPublicKey = None,
                 verifying: UmbralPublicKey = None
                 ):
        delegating_key_details = self._set_cfrag_correctness_key("delegating", delegating)
        receiving_key_details = self._set_cfrag_correctness_key("receiving", receiving)
        verifying_key_details = self._set_cfrag_correctness_key("verifying", verifying)

        return delegating_key_details, receiving_key_details, verifying_key_details

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

        return s * g == v + (h * e)

    def attach_cfrag(self, cfrag: CapsuleFrag) -> None:
        self.verify_cfrag(cfrag)
        self._attached_cfrags.append(cfrag)

    def verify_cfrag(self, cfrag):
        return cfrag.verify_correctness(self,
                                        self._cfrag_correctness_keys["delegating"],
                                        self._cfrag_correctness_keys["receiving"],
                                        self._cfrag_correctness_keys["verifying"],
                                        self._umbral_params
                                        )

    def original_components(self) -> Tuple[Point, Point, CurveBN]:
        return self._point_e, self._point_v, self._bn_sig

    def activated_components(self) -> Union[Tuple[None, None, None], Tuple[Point, Point, Point]]:
        return self._point_e_prime, self._point_v_prime, self._point_noninteractive

    def _reconstruct_shamirs_secret(self,
                                    priv_b: Union[UmbralPrivateKey, CurveBN]
                                    ) -> None:
        g = self._umbral_params.g

        if isinstance(priv_b, UmbralPrivateKey):
            pub_b = priv_b.get_pubkey()
            priv_b = priv_b.bn_key
        else:
            pub_b = priv_b * g

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
            xs = [CurveBN.hash(cfrag._kfrag_id, hashed_dh_tuple, params=self._umbral_params)
                  for cfrag in self._attached_cfrags]
            x_0 = CurveBN.hash(id_0, hashed_dh_tuple, params=self._umbral_params)
            lambda_0 = lambda_coeff(x_0, xs)
            e = lambda_0 * cfrag_0._point_e1
            v = lambda_0 * cfrag_0._point_v1

            for cfrag in self._attached_cfrags[1:]:
                if (ni, xcoord) != (cfrag._point_noninteractive, cfrag._point_xcoord):
                    raise ValueError("Attached CFrags are not pairwise consistent")

                x_i = CurveBN.hash(cfrag._kfrag_id, hashed_dh_tuple, params=self._umbral_params)
                lambda_i = lambda_coeff(x_i, xs)
                e = e + (lambda_i * cfrag._point_e1)
                v = v + (lambda_i * cfrag._point_v1)
        else:
            e = cfrag_0._point_e1
            v = cfrag_0._point_v1

        self._point_e_prime = e
        self._point_v_prime = v
        self._point_noninteractive = ni

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

    def __len__(self):
        return len(self._attached_cfrags)


def split_rekey(privkey_a_bn: Union[UmbralPrivateKey, CurveBN],
                signer_a: Signer,
                pubkey_b_point: Union[UmbralPublicKey, Point],
                threshold: int, N: int,
                params: UmbralParameters = None) -> List[KFrag]:
    """
    Creates a re-encryption key from Alice to Bob and splits it in KFrags,
    using Shamir's Secret Sharing. Requires a threshold number of KFrags
    out of N to guarantee correctness of re-encryption.

    Returns a list of KFrags.
    """
    params = params if params is not None else default_params()

    g = params.g

    if isinstance(privkey_a_bn, UmbralPrivateKey):
        pubkey_a_point = privkey_a_bn.get_pubkey().point_key
        privkey_a_bn = privkey_a_bn.bn_key
    else:
        pubkey_a_point = privkey_a_bn * g

    if isinstance(pubkey_b_point, UmbralPublicKey):
        pubkey_b_point = pubkey_b_point.point_key

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
        signature = signer_a(kfrag_validity_message)

        kfrag = KFrag(id=id, bn_key=rk,
                      point_noninteractive=ni, point_commitment=u1,
                      point_xcoord=xcoord, signature=signature)
        kfrags.append(kfrag)

    return kfrags


def reencrypt(kfrag: KFrag, capsule: Capsule, params: UmbralParameters = None,
              provide_proof=True, metadata: bytes = None) -> CapsuleFrag:
    if params is None:
        params = default_params()

    if not capsule.verify():
        raise capsule.NotValid

    rk = kfrag._bn_key
    e1 = rk * capsule._point_e
    v1 = rk * capsule._point_v

    cfrag = CapsuleFrag(point_e1=e1, point_v1=v1, kfrag_id=kfrag._id,
                        point_noninteractive=kfrag._point_noninteractive,
                        point_xcoord=kfrag._point_xcoord)

    if provide_proof:
        prove_cfrag_correctness(cfrag, kfrag, capsule, metadata, params)

    return cfrag


def _encapsulate(alice_pub_key: Point, key_length=32,
                 params: UmbralParameters = None) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""
    params = params if params is not None else default_params()

    g = params.g

    priv_r = CurveBN.gen_rand(params.curve)
    pub_r = priv_r * g

    priv_u = CurveBN.gen_rand(params.curve)
    pub_u = priv_u * g

    h = CurveBN.hash(pub_r, pub_u, params=params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pub_key

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_e=pub_r, point_v=pub_u, bn_sig=s, params=params)


def _decapsulate_original(priv_key: CurveBN, capsule: Capsule, key_length=32,
                          params: UmbralParameters = None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    shared_key = priv_key * (capsule._point_e + capsule._point_v)
    key = kdf(shared_key, key_length)

    if not capsule.verify():
        # Check correctness of original ciphertext
        # (check nº 2) at the end to avoid timing oracles
        raise capsule.NotValid("Capsule verification failed.")

    return key


def _decapsulate_reencrypted(pub_key: Point, priv_key: CurveBN,
                             orig_pub_key: Point, capsule: Capsule,
                             key_length=32, params: UmbralParameters = None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

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

    if not (s * inv_d) * orig_pub_key == (h * e_prime) + v_prime:
        raise GenericUmbralError()
    return key


def encrypt(alice_pubkey: UmbralPublicKey, plaintext: bytes,
            params: UmbralParameters = None) -> Tuple[bytes, Capsule]:
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


def _open_capsule(capsule: Capsule,
                  bob_privkey: UmbralPrivateKey,
                  delegating_pubkey: UmbralPublicKey,
                  alice_pubkey: UmbralPublicKey,
                  params: UmbralParameters = None,
                  check_proof=True) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """
    params = params if params is not None else default_params()

    priv_b = bob_privkey.bn_key
    bob_pubkey = bob_privkey.get_pubkey()

    if check_proof:
        offending_cfrags = []
        for cfrag in capsule._attached_cfrags:
            if not cfrag.verify_correctness(capsule=capsule,
                                            delegating_pubkey=delegating_pubkey,
                                            signing_pubkey=alice_pubkey,
                                            receiving_pubkey=bob_pubkey,
                                            params=params):
                offending_cfrags.append(cfrag)

        if offending_cfrags:
            error_msg = "Decryption error: Some CFrags are not correct"
            raise UmbralCorrectnessError(error_msg, offending_cfrags)

    capsule._reconstruct_shamirs_secret(priv_b)

    key = _decapsulate_reencrypted(bob_pubkey.point_key, priv_b, delegating_pubkey.point_key, capsule, params=params)
    return key


def decrypt(ciphertext: bytes,
            capsule: Capsule,
            decrypting_key: UmbralPrivateKey,
            delegating_pubkey: UmbralPublicKey = None,
            verifying_key: UmbralPublicKey = None,
            params: UmbralParameters = None, check_proof=True) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    params = params if params is not None else default_params()

    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        # (i.e., this is a re-encrypted capsule)

        encapsulated_key = _open_capsule(capsule, decrypting_key, delegating_pubkey, verifying_key,
                                         params=params, check_proof=check_proof)
        dem = UmbralDEM(encapsulated_key)

        original_capsule_bytes = capsule._original_to_bytes()
        cleartext = dem.decrypt(ciphertext, authenticated_data=original_capsule_bytes)
    else:
        # Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        # (i.e., this is an original capsule)
        decapsulated_key = _decapsulate_original(decrypting_key.bn_key, capsule, params=params)
        dem = UmbralDEM(decapsulated_key)

        capsule_bytes = bytes(capsule)
        cleartext = dem.decrypt(ciphertext, authenticated_data=capsule_bytes)

    return cleartext
