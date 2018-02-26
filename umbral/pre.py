import hmac

from typing import Tuple, Union, List

from cryptography.hazmat.primitives.asymmetric import ec
from nacl.secret import SecretBox

from umbral.bignum import BigNum, hash_to_bn
from umbral.config import default_params, default_curve
from umbral.dem import UmbralDEM
from umbral.fragments import KFrag, CapsuleFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.utils import poly_eval, lambda_coeff, kdf, get_curve_keysize_bytes

from io import BytesIO


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

    def _reconstruct_shamirs_secret(self) -> None:
        id_cfrag_pairs = list(self._attached_cfrags.items())
        id_0, cfrag_0 = id_cfrag_pairs[0]
        if len(id_cfrag_pairs) > 1:
            ids = self._attached_cfrags.keys()
            lambda_0 = lambda_coeff(id_0, ids)
            e = lambda_0 * cfrag_0.point_eph_e1
            v = lambda_0 * cfrag_0.point_eph_v1

            for id_i, cfrag in id_cfrag_pairs[1:]:
                lambda_i = lambda_coeff(id_i, ids)
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


class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.point_eph_e2 = e2
        self.point_eph_v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3

    @classmethod
    def from_bytes(cls, data: bytes, curve: ec.EllipticCurve=None):
        """
        Instantiate ChallengeResponse from serialized data.
        """
        curve = curve if curve is not None else default_curve()
        key_size = get_curve_keysize_bytes(curve)
        data = BytesIO(data)

        # BigNums are the keysize in bytes, Points are compressed and the
        # keysize + 1 bytes long.
        e2 = Point.from_bytes(data.read(key_size + 1), curve)
        v2 = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_commitment = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_pok = Point.from_bytes(data.read(key_size + 1), curve)
        kfrag_sig1 = BigNum.from_bytes(data.read(key_size), curve)
        kfrag_sig2 = BigNum.from_bytes(data.read(key_size), curve)
        sig = BigNum.from_bytes(data.read(key_size), curve)

        return cls(e2, v2, kfrag_commitment, kfrag_pok, kfrag_sig1, kfrag_sig2, sig)

    def to_bytes(self) -> bytes:
        """
        Serialize the ChallengeResponse to a bytestring.
        """
        e2 = self.point_eph_e2.to_bytes()
        v2 = self.point_eph_v2.to_bytes()
        kfrag_commitment = self.point_kfrag_commitment.to_bytes()
        kfrag_pok = self.point_kfrag_pok.to_bytes()
        kfrag_sig1 = self.bn_kfrag_sig1.to_bytes()
        kfrag_sig2 = self.bn_kfrag_sig2.to_bytes()
        sig = self.bn_sig.to_bytes()

        result = e2            \
            + v2               \
            + kfrag_commitment \
            + kfrag_pok        \
            + kfrag_sig1       \
            + kfrag_sig2       \
            + sig

        return result

    def __bytes__(self):
        return self.to_bytes()


def gen_priv(curve: ec.EllipticCurve=None) -> BigNum:
    curve = curve if curve is not None else default_curve()
    return BigNum.gen_rand(curve)


def priv2pub(priv: BigNum, params: UmbralParameters=None) -> Point:
    params = params if params is not None else default_params()
    return priv * params.g


def split_rekey(priv_a: Union[UmbralPrivateKey, BigNum],
                pub_b: Union[UmbralPublicKey, Point],
                threshold: int, N: int,
                params: UmbralParameters=None) -> Tuple[List[KFrag], List[Point]]:
    """
    Creates a re-encryption key and splits it using Shamir's Secret Sharing.
    Requires a threshold number of fragments out of N to rebuild rekey.

    Returns rekeys and the vKeys.
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

    h = params.h
    u = params.u

    v_keys = [coeff * h for coeff in coeffs]

    rk_shares = []
    for _ in range(N):
        id_kfrag = BigNum.gen_rand(params.curve)
        rk = poly_eval(coeffs, id_kfrag)

        u1 = rk * u
        y = BigNum.gen_rand(params.curve)

        z1 = hash_to_bn([y * g, id_kfrag, pub_a, pub_b, u1, xcomp], params)
        z2 = y - priv_a * z1

        kFrag = KFrag(id_=id_kfrag, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
        rk_shares.append(kFrag)

    return rk_shares, v_keys


def reencrypt(k_frag: KFrag, capsule: Capsule,
              params: UmbralParameters=None) -> CapsuleFrag:
    params = params if params is not None else default_params()

    if not capsule.verify(params):
        raise capsule.NotValid

    e1 = k_frag.bn_key * capsule._point_eph_e
    v1 = k_frag.bn_key * capsule._point_eph_v

    c_frag = CapsuleFrag(e1=e1, v1=v1, id_=k_frag.bn_id, x=k_frag.point_eph_ni)
    return c_frag


def challenge(k_frag: KFrag, capsule: Capsule, c_frag: CapsuleFrag,
              params: UmbralParameters=None) -> ChallengeResponse:
    params = params if params is not None else default_params()

    e1 = c_frag.point_eph_e1
    v1 = c_frag.point_eph_v1

    e = capsule._point_eph_e
    v = capsule._point_eph_v

    u = params.u
    u1 = k_frag.point_commitment

    t = BigNum.gen_rand(params.curve)
    e2 = t * e
    v2 = t * v
    u2 = t * u

    h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], params)

    z3 = t + h * k_frag.bn_key

    ch_resp = ChallengeResponse(e2=e2, v2=v2, u1=u1, u2=u2,
                                z1=k_frag.bn_sig1, z2=k_frag.bn_sig2, z3=z3)

    # Check correctness of original ciphertext (check nº 2) at the end
    # to avoid timing oracles
    if not capsule.verify(params):
        raise capsule.NotValid("Capsule verification failed.")

    return ch_resp


def check_challenge(capsule: Capsule, c_frag: CapsuleFrag,
                    challenge_resp: ChallengeResponse,
                    pub_a: Point, pub_b: Point,
                    params: UmbralParameters=None) -> bool:
    params = params if params is not None else default_params()

    e = capsule._point_eph_e
    v = capsule._point_eph_v

    e1 = c_frag.point_eph_e1
    v1 = c_frag.point_eph_v1
    xcomp = c_frag.point_eph_ni
    kfrag_id = c_frag.bn_kfrag_id

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

    h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], params)

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


def decapsulate_reencrypted(pub_key: Point, priv_key: BigNum,
                            orig_pub_key: Point, capsule: Capsule,
                            key_length=32, params: UmbralParameters=None) -> bytes:
    """Derive the same symmetric key"""
    params = params if params is not None else default_params()

    xcomp = capsule._point_noninteractive
    d = hash_to_bn([xcomp, pub_key, xcomp * priv_key], params)

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


def encrypt(alice_pubkey: UmbralPublicKey, plaintext: bytes) -> Tuple[bytes, Capsule]:
    """
    Performs an encryption using the UmbralDEM object and encapsulates a key
    for the sender using the public key provided.

    Returns the ciphertext and the KEM Capsule.
    """
    key, capsule = _encapsulate(alice_pubkey.point_key, SecretBox.KEY_SIZE)

    bytes_capsule = bytes(capsule)

    dem = UmbralDEM(key)
    ciphertext = dem.encrypt(plaintext, authenticated_data=bytes_capsule)

    return ciphertext, capsule


def _open_capsule(capsule: Capsule, bob_private_key: UmbralPrivateKey,
                  alice_pub_key: UmbralPublicKey) -> bytes:
    """
    Activates the Capsule from the attached CFrags,
    opens the Capsule and returns what is inside.

    This will often be a symmetric key.
    """
    recp_pub_key = bob_private_key.get_pubkey()
    capsule._reconstruct_shamirs_secret()

    key = decapsulate_reencrypted(
        recp_pub_key.point_key, bob_private_key.bn_key,
        alice_pub_key.point_key, capsule
    )
    return key


def decrypt(capsule: Capsule, priv_key: UmbralPrivateKey,
            ciphertext: bytes, alice_pub_key: UmbralPublicKey=None) -> bytes:
    """
    Opens the capsule and gets what's inside.

    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    if capsule._attached_cfrags:
        # Since there are cfrags attached, we assume this is Bob opening the Capsule.
        bob_priv_key = priv_key
        key = _open_capsule(capsule, bob_priv_key, alice_pub_key)
        dem = UmbralDEM(key)

        bytes_original_capsule = capsule._original_to_bytes()
        cleartext = dem.decrypt(ciphertext, authenticated_data=bytes_original_capsule)
    else:
        key = _decapsulate_original(priv_key.bn_key, capsule)
        dem = UmbralDEM(key)

        bytes_capsule = bytes(capsule)
        cleartext = dem.decrypt(ciphertext, authenticated_data=bytes_capsule)

    return cleartext
