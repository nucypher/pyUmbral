from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from umbral.bignum import BigNum
from umbral.point import Point
from umbral.utils import poly_eval, lambda_coeff


class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.bn_id = id_
        self.point_key = key
        self.point_eph_ni = x
        self.point_commitment = u1
        self.bn_sig1 = z1
        self.bn_sig2 = z2


class Capsule(object):
    def __init__(self, point_eph_e, point_eph_v, bn_sig):
        self.point_eph_e = point_eph_e
        self.point_eph_v = point_eph_v
        self.bn_sig = bn_sig


class CapsuleFrag(object):
    def __init__(self, e1, v1, id_, x):
        self.e1 = e1
        self.v1 = v1
        self.bn_kfrag_id = id_
        self.point_eph_ni = x


class ReconstructedCapsule(object):
    def __init__(self, e_prime, v_prime, x):
        self.e_prime = e_prime
        self.v_prime = v_prime
        self.point_eph_ni = x


class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.e2 = e2
        self.v2 = v2
        self.point_kfrag_commitment = u1
        self.point_kfrag_pok = u2
        self.bn_kfrag_sig1 = z1
        self.bn_kfrag_sig2 = z2
        self.bn_sig = z3


# minVal = (1 << 256) % self.order   (i.e., 2^256 % order)
MINVAL_SECP256K1_HASH_256 = 432420386565659656852420866394968145599


class PRE(object):
    def __init__(self):
        self.backend = default_backend()
        self.curve = ec.SECP256K1()
        self.g = Point.get_generator_from_curve(self.curve)
        self.order = Point.get_order_from_curve(self.curve)

    def hash_to_bn(self, list):

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        for x in list:
            if isinstance(x, Point):
                bytes = x.to_bytes()
            elif isinstance(x, BigNum):
                bytes = int(x).to_bytes(32, byteorder='big')
            else:
                # print(type(x))
                bytes = x
            digest.update(bytes)

        i = 0
        h = 0
        while h < MINVAL_SECP256K1_HASH_256:
            digest_i = digest.copy()
            digest_i.update(i.to_bytes(32, byteorder='big'))
            hash = digest_i.finalize()
            h = int.from_bytes(hash, byteorder='big', signed=False)
            i += 1
        hash_bn = h % int(self.order)
        # print()
        # print("hash_bn: ", hash_bn)
        # print("order: ", int(self.order))
        res = BigNum.from_int(hash_bn, self.curve)
        # print("res: ", int(res))
        return res

    def gen_priv(self):
        return BigNum.gen_rand(self.curve)

    def priv2pub(self, priv):
        return self.g * priv

    def kdf(self, ecpoint, key_length):
        data = ecpoint.to_bytes()

        # TODO: Handle salt somehow
        return HKDF(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(data)

    def split_rekey(self, priv_a, pub_b, threshold, N):

        x = BigNum.gen_rand(self.curve)
        xcomp = self.g * x
        d = self.hash_to_bn([xcomp, pub_b, pub_b * x])

        coeffs = [priv_a * (~d)]
        coeffs += [BigNum.gen_rand(self.curve) for _ in range(threshold - 1)]

        # TODO: change this into public parameters different than g
        h = self.g
        u = self.g

        vKeys = [h * coeff for coeff in coeffs]

        rk_shares = []
        for _ in range(N):
            id_ = BigNum.gen_rand(self.curve)
            rk = poly_eval(coeffs, id_)

            u1 = u * rk
            y = BigNum.gen_rand(self.curve)

            z1 = self.hash_to_bn([xcomp, u1, self.g * y, id_])
            z2 = y - priv_a * z1

            kFrag = KFrag(id_=id_, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys

    def check_kFrag_consistency(self, kFrag, vKeys):
        if vKeys is None or len(vKeys) == 0:
            raise ValueError('vKeys must not be empty')

        # TODO: change this!
        h = self.g
        lh_exp = h * kFrag.point_key

        rh_exp = vKeys[0]
        i_j = kFrag.bn_id
        for vKey in vKeys[1:]:
            rh_exp = rh_exp + (vKey * i_j)
            i_j = i_j * kFrag.bn_id

        return lh_exp == rh_exp

    def check_kFrag_signature(self, kFrag, pub_a):

        u1 = kFrag.point_commitment
        z1 = kFrag.bn_sig1
        z2 = kFrag.bn_sig2
        x  = kFrag.point_eph_ni

        y = (self.g * z2) + (pub_a * z1)

        return z1 == self.hash_to_bn([x, u1, y, kFrag.bn_id])

    def reencrypt(self, kFrag, capsule):

        e1 = capsule.point_eph_e * kFrag.point_key
        v1 = capsule.point_eph_v * kFrag.point_key

        cFrag = CapsuleFrag(e1=e1, v1=v1, id_=kFrag.bn_id, x=kFrag.point_eph_ni)

        # Check correctness of original ciphertext at the end 
        # to avoid timing oracles
        assert self.check_original(capsule), "Generic Umbral Error"
        return cFrag

    def challenge(self, rk, capsule, cFrag):

        e1 = cFrag.e1
        v1 = cFrag.v1

        e = capsule.point_eph_e
        v = capsule.point_eph_v

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = rk.point_commitment

        t = BigNum.gen_rand(self.curve)
        e2 = e * t
        v2 = v * t
        u2 = u * t

        h = self.hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2])

        z3 = t + h * rk.point_key

        ch_resp = ChallengeResponse(e2=e2, v2=v2, u1=u1, u2=u2, z1=rk.bn_sig1, z2=rk.bn_sig2, z3=z3)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert self.check_original(capsule), "Generic Umbral Error"
        return ch_resp

    def check_challenge(self, capsule, cFrag, challenge_resp, pub_a):
        e = capsule.point_eph_e
        v = capsule.point_eph_v

        e1 = cFrag.e1
        v1 = cFrag.v1
        xcomp = cFrag.point_eph_ni
        re_id = cFrag.bn_kfrag_id

        e2 = challenge_resp.e2
        v2 = challenge_resp.v2

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = challenge_resp.point_kfrag_commitment
        u2 = challenge_resp.point_kfrag_pok

        z1 = challenge_resp.bn_kfrag_sig1
        z2 = challenge_resp.bn_kfrag_sig2
        z3 = challenge_resp.bn_sig

        ycomp = (self.g * z2) + (pub_a * z1)

        h = self.hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2])

        check31 = z1 == self.hash_to_bn([xcomp, u1, ycomp, re_id])
        check32 = e * z3 == e2 + (e1 * h)
        check33 = u * z3 == u2 + (u1 * h)

        return check31 & check32 & check33

    def encapsulate(self, pub_key, key_length=32):
        """Generates a symmetric key and its associated KEM ciphertext"""

        priv_r = BigNum.gen_rand(self.curve)
        pub_r = self.g * priv_r

        priv_u = BigNum.gen_rand(self.curve)
        pub_u = self.g * priv_u

        h = self.hash_to_bn([pub_r, pub_u])
        s = priv_u + (priv_r * h)

        shared_key = pub_key * (priv_r + priv_u)

        # Key to be used for symmetric encryption
        key = self.kdf(shared_key, key_length)

        return key, Capsule(point_eph_e=pub_r, point_eph_v=pub_u, bn_sig=s)

    def check_original(self, capsule):

        e = capsule.point_eph_e
        v = capsule.point_eph_v
        s = capsule.bn_sig
        h = self.hash_to_bn([e, v])

        return self.g * s == v + (e * h)

    def decapsulate_original(self, priv_key, capsule, key_length=32):
        """Derive the same symmetric key"""

        shared_key = (capsule.point_eph_e + capsule.point_eph_v) * priv_key
        key = self.kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert self.check_original(capsule), "Generic Umbral Error"
        return key

    def reconstruct_capsule(self, cFrags):
        cFrag_0 = cFrags[0]

        if len(cFrags) > 1:
            ids = [cFrag.bn_kfrag_id for cFrag in cFrags]
            lambda_0 = lambda_coeff(cFrag_0.bn_kfrag_id, ids)
            e = cFrag_0.e1 * lambda_0
            v = cFrag_0.v1 * lambda_0
            for cFrag in cFrags[1:]:
                lambda_i = lambda_coeff(cFrag.bn_kfrag_id, ids)
                e = e + (cFrag.e1 * lambda_i)
                v = v + (cFrag.v1 * lambda_i)

            return ReconstructedCapsule(e_prime=e, v_prime=v, x=cFrag_0.point_eph_ni)
        else: #if len(reencrypted_keys) == 1:
            return ReconstructedCapsule(e_prime=cFrag_0.e1, v_prime=cFrag_0.v1, x=cFrag_0.point_eph_ni)

    def decapsulate_reencrypted(self, pub_key: Point, priv_key: BigNum, capsule, orig_pub_key: Point,
                                orig_ciphertext: Capsule, key_length=32):
        """Derive the same symmetric key"""

        xcomp = capsule.point_eph_ni
        d = self.hash_to_bn([xcomp, pub_key, xcomp * priv_key])

        e_prime = capsule.e_prime
        v_prime = capsule.v_prime

        shared_key = (e_prime + v_prime) * d
        key = self.kdf(shared_key, key_length)

        e = orig_ciphertext.point_eph_e
        v = orig_ciphertext.point_eph_v
        s = orig_ciphertext.bn_sig
        h = self.hash_to_bn([e, v])
        inv_d = ~d
        assert orig_pub_key * (s * inv_d) == v_prime + (e_prime * h), "Generic Umbral Error"

        return key
