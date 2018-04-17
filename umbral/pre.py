import hmac

from typing import Tuple, Union, List

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from umbral.bignum import BigNum, hash_to_bn
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


class Capsule(object):

    def __init__(self,
                 point_eph_e=None,
                 point_eph_v=None,
                 bn_sig=None,
                 e_prime=None,
                 v_prime=None,
                 noninteractive_point=None):

        if isinstance(point_eph_e, Point):
            if not isinstance(point_eph_v, Point) or not isinstance(bn_sig, BigNum):
                raise TypeError("Need point_eph_e, point_eph_v, and bn_sig to make a Capsule.")
        elif isinstance(e_prime, Point):
            if not isinstance(v_prime, Point) or not isinstance(noninteractive_point, Point):
                raise TypeError("Need e_prime, v_prime, and noninteractive_point to make an activated Capsule.")
        else:
            raise TypeError(
                "Need proper Points and/or BigNums to make a Capsule.  Pass either Alice's data or Bob's. " \
                "Passing both is also fine.")

        self._point_eph_e = point_eph_e
        self._point_eph_v = point_eph_v
        self._bn_sig = bn_sig

        self._point_eph_e_prime = e_prime
        self._point_eph_v_prime = v_prime
        self._point_noninteractive = noninteractive_point

        self._attached_cfrags = {}
        self._contents = None

    class NotValid(ValueError):
        """
        raised if the capusle does not pass verification.
        """

    @classmethod
    def from_bytes(cls, capsule_bytes: bytes, curve: ec.EllipticCurve = None):
        """
        Instantiates a Capsule object from the serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        capsule_buff = BytesIO(capsule_bytes)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        if len(capsule_bytes) == 197:
            eph_e = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            eph_v = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            sig = BigNum.from_bytes(capsule_buff.read(key_size), curve)
            e_prime = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            v_prime = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            eph_ni = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
        else:
            eph_e = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            eph_v = Point.from_bytes(capsule_buff.read(key_size + 1), curve)
            sig = BigNum.from_bytes(capsule_buff.read(key_size), curve)
            e_prime = v_prime = eph_ni = None

        return cls(point_eph_e=eph_e, point_eph_v=eph_v, bn_sig=sig,
                   e_prime=e_prime, v_prime=v_prime, noninteractive_point=eph_ni)

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

        e = self._point_eph_e
        v = self._point_eph_v
        s = self._bn_sig
        h = hash_to_bn([e, v], params)

        return s * params.g == v + (h * e)

    def attach_cfrag(self, cfrag: CapsuleFrag) -> None:
        self._attached_cfrags[cfrag.bn_kfrag_id] = cfrag

    def original_components(self) -> Tuple[Point, Point, BigNum]:
        return self._point_eph_e, self._point_eph_v, self._bn_sig

    def activated_components(self) -> Union[Tuple[None, None, None], Tuple[Point, Point, Point]]:
        return self._point_eph_e_prime, self._point_eph_v_prime, self._point_noninteractive

    def _reconstruct_shamirs_secret(self, 
                                    pub_a: Union[UmbralPublicKey, Point], 
                                    priv_b: Union[UmbralPrivateKey, BigNum],
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

        id_cfrag_pairs = list(self._attached_cfrags.items())
        id_0, cfrag_0 = id_cfrag_pairs[0]
        x_0 = hash_to_bn([id_0, hashed_dh_tuple], params)
        if len(id_cfrag_pairs) > 1:
            xs = [hash_to_bn([_id, hashed_dh_tuple], params) 
                    for _id in self._attached_cfrags.keys()]
            lambda_0 = lambda_coeff(x_0, xs)
            e = lambda_0 * cfrag_0.point_eph_e1
            v = lambda_0 * cfrag_0.point_eph_v1

            for id_i, cfrag in id_cfrag_pairs[1:]:
                x_i = hash_to_bn([id_i, hashed_dh_tuple], params)
                lambda_i = lambda_coeff(x_i, xs)
                e = e + (lambda_i * cfrag.point_eph_e1)
                v = v + (lambda_i * cfrag.point_eph_v1)
        else:
            e = cfrag_0.point_eph_e1
            v = cfrag_0.point_eph_v1

        self._point_eph_e_prime = e
        self._point_eph_v_prime = v
        self._point_noninteractive = cfrag_0.point_eph_ni

    def __bytes__(self):
        return self.to_bytes()

    def __eq__(self, other):
        """
        If both Capsules are activated, we compare only the activated components.
        Otherwise, we compare only original components.
        Each component is compared to its counterpart in constant time per the __eq__ of Point and BigNum.
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





def split_rekey(priv_a: Union[UmbralPrivateKey, BigNum],
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

    x = BigNum.gen_rand(params.curve)
    xcomp = x * g
    d = hash_to_bn([xcomp, pub_b, pub_b * x], params)

    coeffs = [priv_a * (~d)]
    coeffs += [BigNum.gen_rand(params.curve) for _ in range(threshold - 1)]

    u = params.u

    g_ab = priv_a * pub_b

    blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
    blake2b.update(pub_a.to_bytes())
    blake2b.update(pub_b.to_bytes())
    blake2b.update(g_ab.to_bytes())
    hashed_dh_tuple = blake2b.finalize()

    kfrags = []
    for _ in range(N):
        id_kfrag = BigNum.gen_rand(params.curve)

        share_x = hash_to_bn([id_kfrag, hashed_dh_tuple], params)

        rk = poly_eval(coeffs, share_x)

        u1 = rk * u
        y = BigNum.gen_rand(params.curve)

        z1 = hash_to_bn([y * g, id_kfrag, pub_a, pub_b, u1, xcomp], params)
        z2 = y - priv_a * z1

        kfrag = KFrag(id_=id_kfrag, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
        kfrags.append(kfrag)

    return kfrags


def reencrypt(kfrag: KFrag, capsule: Capsule,
              params: UmbralParameters=None, challenge_metadata: bytes=None) -> CapsuleFrag:
    if params is None:
        params = default_params()

    if not capsule.verify(params):
        raise capsule.NotValid

    e1 = kfrag.bn_key * capsule._point_eph_e
    v1 = kfrag.bn_key * capsule._point_eph_v

    cfrag = CapsuleFrag(e1=e1, v1=v1, id_=kfrag.bn_id, x=kfrag.point_eph_ni)

    proof = _prove_correctness(kfrag, capsule, cfrag, challenge_metadata, params)

    cfrag.attach_correctness_proof(proof)

    return cfrag


def _prove_correctness(kfrag: KFrag, capsule: Capsule, 
              cfrag: CapsuleFrag, challenge_metadata: bytes=None,
              params: UmbralParameters=None) -> CorrectnessProof:
    params = params if params is not None else default_params()

    e1 = cfrag.point_eph_e1
    v1 = cfrag.point_eph_v1

    e = capsule._point_eph_e
    v = capsule._point_eph_v

    u = params.u
    u1 = kfrag.point_commitment

    t = BigNum.gen_rand(params.curve)
    e2 = t * e
    v2 = t * v
    u2 = t * u

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if challenge_metadata:
        hash_input.append(challenge_metadata)
    
    h = hash_to_bn(hash_input, params)

    z3 = t + h * kfrag.bn_key

    ch_resp = CorrectnessProof(e2=e2, v2=v2, u1=u1, u2=u2,
                                z1=kfrag.bn_sig1, z2=kfrag.bn_sig2, z3=z3)

    # Check correctness of original ciphertext (check nº 2) at the end
    # to avoid timing oracles
    if not capsule.verify(params):
        raise capsule.NotValid("Capsule verification failed.")

    return ch_resp


def _check_challenge(capsule: Capsule, cfrag: CapsuleFrag,
                    challenge_resp: CorrectnessProof, 
                    pub_a: Point, pub_b: Point, challenge_metadata: bytes=None,
                    params: UmbralParameters=None) -> bool:
    params = params if params is not None else default_params()

    e = capsule._point_eph_e
    v = capsule._point_eph_v

    e1 = cfrag.point_eph_e1
    v1 = cfrag.point_eph_v1
    xcomp = cfrag.point_eph_ni
    kfrag_id = cfrag.bn_kfrag_id

    e2 = challenge_resp.point_eph_e2
    v2 = challenge_resp.point_eph_v2

    g = params.g
    u = params.u

    u1 = challenge_resp.point_kfrag_commitment
    u2 = challenge_resp.point_kfrag_pok

    z1 = challenge_resp.bn_kfrag_sig1
    z2 = challenge_resp.bn_kfrag_sig2
    z3 = challenge_resp.bn_sig

    g_y = (z2 * g) + (z1 * pub_a)

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if challenge_metadata:
        hash_input.append(challenge_metadata)
    
    h = hash_to_bn(hash_input, params)

    check31 = z1 == hash_to_bn([g_y, kfrag_id, pub_a, pub_b, u1, xcomp], params)
    check32 = z3 * e == e2 + (h * e1)
    check33 = z3 * u == u2 + (h * u1)
    check34 = z3 * v == v2 + (h * v1)

    return check31 & check32 & check33 & check34


def _encapsulate(alice_pub_key: Point, key_length=32,
                 params: UmbralParameters=None) -> Tuple[bytes, Capsule]:
    """Generates a symmetric key and its associated KEM ciphertext"""
    params = params if params is not None else default_params()

    g = params.g

    priv_r = BigNum.gen_rand(params.curve)
    pub_r = priv_r * g

    priv_u = BigNum.gen_rand(params.curve)
    pub_u = priv_u * g

    h = hash_to_bn([pub_r, pub_u], params)
    s = priv_u + (priv_r * h)

    shared_key = (priv_r + priv_u) * alice_pub_key

    # Key to be used for symmetric encryption
    key = kdf(shared_key, key_length)

    return key, Capsule(point_eph_e=pub_r, point_eph_v=pub_u, bn_sig=s)


def _decapsulate_original(priv_key: BigNum, capsule: Capsule, key_length=32,
                          params: UmbralParameters=None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    shared_key = priv_key * (capsule._point_eph_e+capsule._point_eph_v)
    key = kdf(shared_key, key_length)

    if not capsule.verify(params):
        # Check correctness of original ciphertext
        # (check nº 2) at the end to avoid timing oracles
        raise capsule.NotValid("Capsule verification failed.")

    return key


def _decapsulate_reencrypted(pub_key: Point, priv_key: BigNum,
                            orig_pub_key: Point, capsule: Capsule,
                            key_length=32, params: UmbralParameters=None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    xcomp = capsule._point_noninteractive
    d = hash_to_bn([xcomp, pub_key, priv_key * xcomp], params)

    e_prime = capsule._point_eph_e_prime
    v_prime = capsule._point_eph_v_prime

    shared_key = d * (e_prime + v_prime)

    key = kdf(shared_key, key_length)

    e = capsule._point_eph_e
    v = capsule._point_eph_v
    s = capsule._bn_sig
    h = hash_to_bn([e, v], params)
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


def _open_capsule(capsule: Capsule, bob_private_key: UmbralPrivateKey,
                  alice_pub_key: UmbralPublicKey, params: UmbralParameters=None) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """
    params = params if params is not None else default_params()

    priv_b = bob_private_key.bn_key
    pub_b = priv_b * params.g

    pub_a = alice_pub_key.point_key

    capsule._reconstruct_shamirs_secret(pub_a, priv_b, params=params)

    key = _decapsulate_reencrypted(pub_b, priv_b, pub_a, capsule, params=params)
    return key


def decrypt(ciphertext: bytes, capsule: Capsule,
        priv_key: UmbralPrivateKey, alice_pub_key: UmbralPublicKey=None, params: UmbralParameters=None) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    params = params if params is not None else default_params()

    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        bob_priv_key = priv_key
        key = _open_capsule(capsule, bob_priv_key, alice_pub_key, params=params)
        dem = UmbralDEM(key)

        original_capsule_bytes = capsule._original_to_bytes()
        cleartext = dem.decrypt(ciphertext, authenticated_data=original_capsule_bytes)
    else:
        # Since there aren't cfrags attached, we assume this is Alice opening the Capsule.
        key = _decapsulate_original(priv_key.bn_key, capsule, params=params)
        dem = UmbralDEM(key)

        capsule_bytes = bytes(capsule)
        cleartext = dem.decrypt(ciphertext, authenticated_data=capsule_bytes)

    return cleartext
