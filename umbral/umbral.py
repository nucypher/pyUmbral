from cryptography.hazmat.primitives.asymmetric import ec
from nacl.secret import SecretBox

from umbral.bignum import BigNum
from umbral.config import default_params, default_curve
from umbral.dem import UmbralDEM
from umbral.fragments import KFrag, CapsuleFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.utils import poly_eval, lambda_coeff, hash_to_bn, kdf


class Capsule(object):
    def __init__(self,
                 point_eph_e=None,
                 point_eph_v=None,
                 bn_sig=None,
                 e_prime=None,
                 v_prime=None,
                 noninteractive_point=None):

        if not point_eph_e and not e_prime:
            raise ValueError(
                "Can't make a Capsule from nothing.  Pass either Alice's data (ie, point_eph_e) or Bob's (e_prime). \
                Passing both is also fine.")

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
    def from_bytes(cls, capsule_bytes: bytes, curve: ec.EllipticCurve):
        """
        Instantiates a Capsule object from the serialized data.
        """
        # TODO: This has gotten utterly unwieldy.  We need a programmatic splitting facility (let's just use BytestringSplitter?)
        if len(capsule_bytes) == 197:
            eph_e = Point.from_bytes(capsule_bytes[0:33], curve)
            eph_v = Point.from_bytes(capsule_bytes[33:66], curve)
            sig = BigNum.from_bytes(capsule_bytes[66:98], curve)
            e_prime = Point.from_bytes(capsule_bytes[98:131], curve)
            v_prime = Point.from_bytes(capsule_bytes[131:164], curve)
            eph_ni = Point.from_bytes(capsule_bytes[164:197], curve)
        else:
            eph_e = Point.from_bytes(capsule_bytes[0:33], curve)
            eph_v = Point.from_bytes(capsule_bytes[33:66], curve)
            sig = BigNum.from_bytes(capsule_bytes[66:98], curve)
            e_prime = v_prime = eph_ni = None

        return cls(point_eph_e=eph_e, point_eph_v=eph_v, bn_sig=sig,
                   e_prime=e_prime, v_prime=v_prime, noninteractive_point=eph_ni)

    def to_bytes(self):
        """
        Serialize the Capsule into a bytestring.
        """
        bytes_representation = bytes().join(c.to_bytes() for c in self.original_components())
        if all(self.activated_components()):
            bytes_representation += bytes().join(c.to_bytes() for c in self.activated_components())
        return bytes_representation

    def verify(self, params: UmbralParameters):

        e = self._point_eph_e
        v = self._point_eph_v
        s = self._bn_sig
        h = hash_to_bn([e, v], params)

        return s * params.g == v + (h * e)

    def attach_cfrag(self, cfrag: CapsuleFrag):
        self._attached_cfrags[cfrag.bn_kfrag_id] = cfrag

    def original_components(self):
        return self._point_eph_e, self._point_eph_v, self._bn_sig

    def activated_components(self):
        return self._point_eph_e_prime, self._point_eph_v_prime, self._point_noninteractive

    def _reconstruct_shamirs_secret(self):
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
        self.to_bytes()

    def __eq__(self, other):
        if all(self.activated_components() + other.activated_components()):
            activated_match = self.activated_components() == other.activated_components()
            return activated_match
        elif all(self.original_components() + other.original_components()):
            original_match = self.original_components() == other.original_components()
            return original_match
        else:
            return False


class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.point_eph_e2 = e2
        self.point_eph_v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3

    @staticmethod
    def from_bytes(data: bytes, curve: ec.EllipticCurve):
        """
        Instantiate ChallengeResponse from serialized data.
        """
        e2 = Point.from_bytes(data[0:33], curve)
        v2 = Point.from_bytes(data[33:66], curve)
        kfrag_commitment = Point.from_bytes(data[66:99], curve)
        kfrag_pok = Point.from_bytes(data[99:132], curve)
        kfrag_sig1 = BigNum.from_bytes(data[132:164], curve)
        kfrag_sig2 = BigNum.from_bytes(data[164:196], curve)
        sig = BigNum.from_bytes(data[196:228], curve)

        return ChallengeResponse(e2, v2, kfrag_commitment, kfrag_pok,
                                 kfrag_sig1, kfrag_sig2, sig)

    def to_bytes(self):
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

        return (e2 + v2 + kfrag_commitment + kfrag_pok + kfrag_sig1
                + kfrag_sig2 + sig)

    def __bytes__(self):
        return self.to_bytes()


class PRE(object):
    def __init__(self, params: UmbralParameters = None):
        if params is None:
            params = UmbralParameters()
        self.params = params

    def gen_priv(self):
        return BigNum.gen_rand(self.params.curve)

    def priv2pub(self, priv):
        g = self.params.g
        return priv * g

    def split_rekey(self, priv_a, pub_b, threshold, N):
        """
        Creates a re-encryption key and splits it using Shamir's Secret Sharing.
        Requires a threshold number of fragments out of N to rebuild rekey.

        Returns rekeys and the vKeys.
        """
        if type(priv_a) == UmbralPrivateKey:
            priv_a = priv_a.bn_key

        if type(pub_b) == UmbralPublicKey:
            pub_b = pub_b.point_key

        g = self.params.g

        pub_a = priv_a * g

        x = BigNum.gen_rand(self.params.curve)
        xcomp = x * g
        d = hash_to_bn([xcomp, pub_b, pub_b * x], self.params)

        coeffs = [priv_a * (~d)]
        coeffs += [BigNum.gen_rand(self.params.curve) for _ in range(threshold - 1)]

        h = self.params.h
        u = self.params.u

        vKeys = [coeff * h for coeff in coeffs]

        rk_shares = []
        for _ in range(N):
            id_kfrag = BigNum.gen_rand(self.params.curve)
            rk = poly_eval(coeffs, id_kfrag)

            u1 = rk * u
            y = BigNum.gen_rand(self.params.curve)

            z1 = hash_to_bn([y * g, id_kfrag, pub_a, pub_b, u1, xcomp], self.params)
            z2 = y - priv_a * z1

            kFrag = KFrag(id_=id_kfrag, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys

    def reencrypt(self, kFrag, capsule):
        if not capsule.verify(self.params):
            raise capsule.NotValid

        e1 = kFrag.bn_key * capsule._point_eph_e
        v1 = kFrag.bn_key * capsule._point_eph_v

        cFrag = CapsuleFrag(e1=e1, v1=v1, id_=kFrag.bn_id, x=kFrag.point_eph_ni)
        return cFrag

    def challenge(self, rk, capsule, cFrag):
        e1 = cFrag.point_eph_e1
        v1 = cFrag.point_eph_v1

        e = capsule._point_eph_e
        v = capsule._point_eph_v

        u = self.params.u
        u1 = rk.point_commitment

        t = BigNum.gen_rand(self.params.curve)
        e2 = t * e
        v2 = t * v
        u2 = t * u

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        z3 = t + h * rk.bn_key

        ch_resp = ChallengeResponse(e2=e2, v2=v2, u1=u1, u2=u2, z1=rk.bn_sig1, z2=rk.bn_sig2, z3=z3)

        # Check correctness of original ciphertext (check nº 2) at the end
        # to avoid timing oracles
        assert capsule.verify(self.params), "Generic Umbral Error"
        return ch_resp

    def check_challenge(self, capsule, cFrag, challenge_resp, pub_a, pub_b):
        e = capsule._point_eph_e
        v = capsule._point_eph_v

        e1 = cFrag.point_eph_e1
        v1 = cFrag.point_eph_v1
        xcomp = cFrag.point_eph_ni
        kfrag_id = cFrag.bn_kfrag_id

        e2 = challenge_resp.point_eph_e2
        v2 = challenge_resp.point_eph_v2

        g = self.params.g

        u = self.params.u
        u1 = challenge_resp.point_kfrag_commitment
        u2 = challenge_resp.point_kfrag_pok

        z1 = challenge_resp.bn_kfrag_sig1
        z2 = challenge_resp.bn_kfrag_sig2
        z3 = challenge_resp.bn_sig

        g_y = (z2 * g) + (z1 * pub_a)

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        check31 = z1 == hash_to_bn([g_y, kfrag_id, pub_a, pub_b, u1, xcomp], self.params)
        check32 = z3 * e == e2 + (h * e1)
        check33 = z3 * u == u2 + (h * u1)

        return check31 & check32 & check33

    def _encapsulate(self, alice_pub_key, key_length=32):
        """Generates a symmetric key and its associated KEM ciphertext"""
        g = self.params.g

        priv_r = BigNum.gen_rand(self.params.curve)
        pub_r = priv_r * g

        priv_u = BigNum.gen_rand(self.params.curve)
        pub_u = priv_u * g

        h = hash_to_bn([pub_r, pub_u], self.params)
        s = priv_u + (priv_r * h)

        shared_key = (priv_r + priv_u) * alice_pub_key

        # Key to be used for symmetric encryption
        key = kdf(shared_key, key_length)

        return key, Capsule(point_eph_e=pub_r, point_eph_v=pub_u, bn_sig=s)

    def _decapsulate_original(self, priv_key, capsule, key_length=32):
        """Derive the same symmetric key"""
        shared_key = priv_key * (capsule._point_eph_e + capsule._point_eph_v)
        key = kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end
        # to avoid timing oracles
        assert capsule.verify(self.params), "Generic Umbral Error"
        return key

    def decapsulate_reencrypted(self, pub_key: Point, priv_key: BigNum, orig_pub_key: Point,
                                capsule: Capsule, key_length=32):
        """Derive the same symmetric key"""

        xcomp = capsule._point_noninteractive
        d = hash_to_bn([xcomp, pub_key, xcomp * priv_key], self.params)

        e_prime = capsule._point_eph_e_prime
        v_prime = capsule._point_eph_v_prime

        shared_key = d * (e_prime + v_prime)

        key = kdf(shared_key, key_length)

        e = capsule._point_eph_e
        v = capsule._point_eph_v
        s = capsule._bn_sig
        h = hash_to_bn([e, v], self.params)
        inv_d = ~d

        assert (s * inv_d) * orig_pub_key == (h * e_prime) + v_prime, "Generic Umbral Error"

        return key

    def encrypt(self, pub_key: UmbralPublicKey, data: bytes):
        """
        Performs an encryption using the UmbralDEM object and encapsulates a key
        for the sender using the public key provided.

        Returns the ciphertext and the KEM Capsule.
        """
        key, capsule = self._encapsulate(pub_key.point_key, SecretBox.KEY_SIZE)

        dem = UmbralDEM(key)
        enc_data = dem.encrypt(data)

        return enc_data, capsule

    def _open_capsule(self,
                      capsule: Capsule,
                      bob_private_key: UmbralPrivateKey,
                      alice_pub_key: UmbralPublicKey,
                      ):
        """
        Activates the Capsule from the attached CFrags,
        opens the Capsule and returns what is inside.

        This will often be a symmetric key.
        """
        recp_pub_key = bob_private_key.get_pub_key()
        capsule._reconstruct_shamirs_secret()

        key = self.decapsulate_reencrypted(
            recp_pub_key.point_key, bob_private_key.bn_key,
            alice_pub_key.point_key, capsule
        )
        return key

    def decrypt(self, capsule, priv_key: UmbralPrivateKey,
                ciphertext: bytes, alice_pub_key: UmbralPublicKey=None):
        """
        Opens the capsule and gets what's inside.

        We hope that's a symmetric key, which we use to decrypt the ciphertext
        and return the resulting cleartext.
        """
        if capsule._attached_cfrags:
            # Since there are cfrags attached, we assume this is Bob opening the Capsule.
            bob_priv_key = priv_key
            key = self._open_capsule(capsule, bob_priv_key, alice_pub_key)
            dem = UmbralDEM(key)
            cleartext = dem.decrypt(ciphertext)
            return cleartext
        else:
            # Without cfrags, only Alice can open this Capsule.
            alice_priv_key = priv_key
            key = self._decapsulate_original(alice_priv_key.bn_key, capsule)
            dem = UmbralDEM(key)
            cleartext = dem.decrypt(ciphertext)
            return cleartext
