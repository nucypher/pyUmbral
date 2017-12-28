from umbral.bignum import BigNum
from umbral.point import Point
from umbral.utils import poly_eval
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class RekeyFrag(object):
    def __init__(self, id, key, xcomp, u1, z1, z2):
        self.id = id
        self.key = key
        self.xcomp = xcomp
        self.u1 = u1
        self.z1 = z1
        self.z2 = z2


class CiphertextKEM(object):
    def __init__(self, e, v, s):
        self.e = e
        self.v = v
        self.s = s


class CiphertextFrag(object):
    def __init__(self, e_r, v_r, id_r, x):
        self.e_r = e_r
        self.v_r = v_r
        self.id_r = id_r
        self.x = x

class CiphertextCombined(object):
    def __init__(self, e, v, x, u1, z1, z2):
        self.e = e
        self.v = v
        self.x = x
        self.u1 = u1
        self.z1 = z1
        self.z2 = z2


class ChallengeResponse(object):
    def __init__(self, e_t, v_t, u1, u2, z1, z2, z3):
        self.e_r = e_r
        self.v_r = v_r
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
        print()
        print("hash_bn: ", hash_bn)
        print("order: ", int(self.order))
        res = BigNum.from_int(hash_bn, self.curve)
        print("res: ", int(res))
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
            id = BigNum.gen_rand(self.curve)
            rk = poly_eval(coeffs, id)

            u1 = u * rk
            y  = BigNum.gen_rand(self.curve)

            z1 = self.hash_to_bn([xcomp, u1, self.g * y, id])
            z2 = y - priv_a * z1

            kFrag = RekeyFrag(id=id, key=rk, xcomp=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

        return rk_shares, vKeys
    
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
        h = self.hash_points_to_bn([e, v])

        return self.g * s == v + (e * h)

    def decapsulate_original(self, priv_key, ciphertext_kem, key_length=32):
        """Derive the same symmetric key"""

        shared_key = (ciphertext_kem.e + ciphertext_kem.v) * priv_key
        key = self.kdf(shared_key, key_length)

        # Check correctness of original ciphertext (check nº 2) at the end 
        # to avoid timing oracles
        # assert self.check_original(ciphertext_kem), "Generic Umbral Error"
        return key

    


        
