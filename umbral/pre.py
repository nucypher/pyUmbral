from cryptography.hazmat.primitives.asymmetric import ec

from umbral.point import Point, BigNum
from umbral.utils import hash_to_bn, kdf, poly_eval


class UmbralParameters(object):
    def __init__(self):
        self.curve = ec.SECP256K1()
        self.g = Point.get_generator_from_curve(self.curve)
        self.order = Point.get_order_from_curve(self.curve)
        self.h = Point.gen_rand(self.curve)
        self.u = Point.gen_rand(self.curve)


class PRE(object):
    def __init__(self, params: UmbralParameters):
        self.params = params

    def gen_priv(self):
        return BigNum.gen_rand(self.params.curve)

    def priv2pub(self, priv):
        g = self.params.g
        return g * priv

    def split_rekey(self, priv_a, pub_b, threshold, N):
        g = self.params.g

        pub_a = g * priv_a

        x = BigNum.gen_rand(self.params.curve)
        xcomp = g * x
        d = hash_to_bn([xcomp, pub_b, pub_b * x], self.params)

        coeffs = [priv_a * (~d)]
        coeffs += [BigNum.gen_rand(self.params.curve) for _ in range(threshold - 1)]

        h = self.params.h
        u = self.params.u

        vKeys = [h * coeff for coeff in coeffs]

        rk_shares = []
        for _ in range(N):
            id_kfrag = BigNum.gen_rand(self.params.curve)
            rk = poly_eval(coeffs, id_kfrag)

            u1 = u * rk
            y = BigNum.gen_rand(self.params.curve)

            z1 = hash_to_bn([g * y, id_kfrag, pub_a, pub_b, u1, xcomp], self.params)
            z2 = y - priv_a * z1

            from umbral.umbral import KFrag  # TODO: Again, maybe just return the elements.
            kFrag = KFrag(id_=id_kfrag, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys

    def reencrypt(self, kFrag, capsule):
        # TODO: Put the assert at the end, but exponentiate by a randon number when false?
        assert capsule.verify(self.params), "Generic Umbral Error"

        e1 = capsule._point_eph_e * kFrag.bn_key
        v1 = capsule._point_eph_v * kFrag.bn_key

        from umbral.capsule import CapsuleFrag  # TODO
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
        e2 = e * t
        v2 = v * t
        u2 = u * t

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        z3 = t + h * rk.bn_key

        from umbral.umbral import ChallengeResponse  # TODO
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

        g_y = (g * z2) + (pub_a * z1)

        h = hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2], self.params)

        check31 = z1 == hash_to_bn([g_y, kfrag_id, pub_a, pub_b, u1, xcomp], self.params)
        check32 = e * z3 == e2 + (e1 * h)
        check33 = u * z3 == u2 + (u1 * h)

        return check31 & check32 & check33

    def encapsulate(self, pub_key, key_length=32):
        """Generates a symmetric key and its associated KEM ciphertext"""
        g = self.params.g

        priv_r = BigNum.gen_rand(self.params.curve)
        pub_r = g * priv_r

        priv_u = BigNum.gen_rand(self.params.curve)
        pub_u = g * priv_u

        h = hash_to_bn([pub_r, pub_u], self.params)
        s = priv_u + (priv_r * h)

        shared_key = pub_key * (priv_r + priv_u)

        # Key to be used for symmetric encryption
        key = kdf(shared_key, key_length)

        from umbral.capsule import Capsule  # TODO: Do this better.  Maybe just pass the elements and instantiate in the caller.
        return key, Capsule(point_eph_e=pub_r, point_eph_v=pub_u, bn_sig=s)

    def decapsulate_original(self, priv_key, capsule, key_length=32):
        """Derive the same symmetric key"""

        shared_key = (capsule._point_eph_e + capsule._point_eph_v) * priv_key
        key = kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end
        # to avoid timing oracles
        assert capsule.verify(self.params), "Generic Umbral Error"
        return key

    def decapsulate_reencrypted(self, pub_key: Point, priv_key: BigNum, orig_pub_key: Point,
                                capsule: "Capsule", key_length=32):
        """Derive the same symmetric key"""

        xcomp = capsule._point_noninteractive

        d = hash_to_bn([xcomp, pub_key, xcomp * priv_key], self.params)
        shared_key = (capsule._point_eph_e_prime + capsule._point_eph_v_prime) * d
        key_bytes = kdf(shared_key, key_length)

        if capsule._point_eph_e:
            # TODO: So, here, we have Alice's data too.  What's actually going on here?
            e = capsule._point_eph_e
            v = capsule._point_eph_v
            s = capsule._bn_sig
            h = hash_to_bn([e, v], self.params)
            inv_d = ~d
            assert orig_pub_key * (s * inv_d) == capsule._point_eph_v_prime + (
                capsule._point_eph_e_prime * h), "Generic Umbral Error"

        return key_bytes
