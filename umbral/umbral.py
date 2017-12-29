from umbral.bignum import BigNum
from umbral.point import Point
from umbral.utils import poly_eval,lambda_coeff
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KFrag(object):
    def __init__(self, id_, key, x, u1, z1, z2):
        self.id = id_
        self.key = key
        self.x = x
        self.u1 = u1
        self.z1 = z1
        self.z2 = z2

class CiphertextKEM(object):
    def __init__(self, e, v, s):
        self.e = e
        self.v = v
        self.s = s

class CiphertextFrag(object):
    def __init__(self, e1, v1, id_, x):
        self.e1 = e1
        self.v1 = v1
        self.id = id_
        self.x = x

class CiphertextCombined(object):
    def __init__(self, e_prime, v_prime, x):
        self.e_prime = e_prime
        self.v_prime = v_prime
        self.x = x

class ChallengeResponse(object):
    def __init__(self, e2, v2, u1, u2, z1, z2, z3):
        self.e2 = e2
        self.v2 = v2
        self.u1 = u1
        self.u2 = u2
        self.z1 = z1
        self.z2 = z2
        self.z3 = z3

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
                bytes  = x.to_bytes()
            elif isinstance(x, BigNum):
                bytes = int(x).to_bytes(32, byteorder='big')
            else:
                #print(type(x))
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
        #print()
        #print("hash_bn: ", hash_bn)
        #print("order: ", int(self.order))
        res = BigNum.from_int(hash_bn, self.curve)
        #print("res: ", int(res))
        return res


    def gen_priv(self):
        return BigNum.gen_rand(self.curve)
        #return ec.generate_private_key(ec.SECP256K1(), default_backend())

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
        # print([xcomp, pub_b, pub_b ** x])
        #print("d: ", int(d))

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
            y  = BigNum.gen_rand(self.curve)

            z1 = self.hash_to_bn([xcomp, u1, self.g * y, id_])
            z2 = y - priv_a * z1

            kFrag = KFrag(id_=id_, key=rk, x=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys

    def reencrypt(self, rk, ciphertext_kem):

        e1 = ciphertext_kem.e * rk.key
        v1 = ciphertext_kem.v * rk.key

        reenc = CiphertextFrag(e1=e1, v1=v1, id_=rk.id, x=rk.x)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert self.check_original(ciphertext_kem), "Generic Umbral Error"
        return reenc

    def challenge(self, rk, ciphertext_kem, cFrag):

        e1 = cFrag.e1
        v1 = cFrag.v1

        e = ciphertext_kem.e
        v = ciphertext_kem.v

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = rk.u1

        t = BigNum.gen_rand(self.curve)
        e2 = e * t
        v2 = v * t
        u2 = u * t

        h = self.hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2])

        z3 = t + h * rk.key

        ch_resp = ChallengeResponse(e2=e2, v2=v2, u1=u1, u2=u2, z1=rk.z1, z2=rk.z2, z3=z3)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert self.check_original(ciphertext_kem), "Generic Umbral Error"
        return ch_resp

    def check_challenge(self, ciphertext_kem, ciphertext_frag, challenge_resp, pub_a):
        e = ciphertext_kem.e
        v = ciphertext_kem.v

        e1 = ciphertext_frag.e1
        v1 = ciphertext_frag.v1
        xcomp = ciphertext_frag.x
        re_id = ciphertext_frag.id

        e2 = challenge_resp.e2
        v2 = challenge_resp.v2

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = challenge_resp.u1
        u2 = challenge_resp.u2

        z1 = challenge_resp.z1
        z2 = challenge_resp.z2
        z3 = challenge_resp.z3

        ycomp = (self.g * z2) + (pub_a * z1)

        h = self.hash_to_bn([e, e1, e2, v, v1, v2, u, u1, u2])
        #print(h)

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

        return key, CiphertextKEM(e=pub_r, v=pub_u, s=s)

    def check_original(self, ciphertext_kem):

        e = ciphertext_kem.e
        v = ciphertext_kem.v
        s = ciphertext_kem.s
        h = self.hash_to_bn([e, v])

        return self.g * s == v + (e * h)

    def decapsulate_original(self, priv_key, ciphertext_kem, key_length=32):
        """Derive the same symmetric key"""

        shared_key = (ciphertext_kem.e + ciphertext_kem.v) * priv_key
        key = self.kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        assert self.check_original(ciphertext_kem), "Generic Umbral Error"
        return key

    def combine(self, cFrags):
        cFrag_0 = cFrags[0]
        
        if len(cFrags) > 1:
            ids = [cFrag.id for cFrag in cFrags]
            lambda_0 = lambda_coeff(cFrag_0.id, ids)
            e = cFrag_0.e1 * lambda_0
            v = cFrag_0.v1 * lambda_0
            for cFrag in cFrags[1:]:
                lambda_i = lambda_coeff(cFrag.id, ids)
                e = e + (cFrag.e1 * lambda_i)
                v = v + (cFrag.v1 * lambda_i)

            return CiphertextCombined(e_prime=e, v_prime=v, x=cFrag_0.x)

        else: #if len(reencrypted_keys) == 1:
            return CiphertextCombined(e_prime=cFrag_0.e1, v_prime=cFrag_0.v1, x=cFrag_0.x)

    def decapsulate_reencrypted(self, pub_key, priv_key, ctxt_combined, orig_pk, orig_ciphertext, key_length=32):
        """Derive the same symmetric key"""

        xcomp = ctxt_combined.x
        d = self.hash_to_bn([xcomp, pub_key, xcomp * priv_key])

        e_prime = ctxt_combined.e_prime
        v_prime = ctxt_combined.v_prime
        
        shared_key = (e_prime + v_prime) * d
        key = self.kdf(shared_key, key_length)

        e = orig_ciphertext.e
        v = orig_ciphertext.v
        s = orig_ciphertext.s
        h = self.hash_to_bn([e, v])
        inv_d = ~d
        assert orig_pk * (s * inv_d) == v_prime + (e_prime * h), "Generic Umbral Error"

        return key
        
