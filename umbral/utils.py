from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from umbral.bignum import BigNum
from umbral.point import Point

def lambda_coeff(id_i, selected_ids):
    ids = [x for x in selected_ids if x != id_i]

    if not ids:
        return None

    div_0 = ~(ids[0] - id_i)
    result = ids[0] * div_0
    for id_j in ids[1:]:
        div_j = ~(id_j - id_i)
        result = result * (id_j * div_j)

    return result

def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, -1):
        result = ((result * x) + coeff[i])

    return result

# minVal = (1 << 256) % self.order   (i.e., 2^256 % order)
MINVAL_SECP256K1_HASH_256 = 432420386565659656852420866394968145599

def hash_to_bn(list, params):
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
    hash_bn = h % int(params.order)
    # print()
    # print("hash_bn: ", hash_bn)
    # print("order: ", int(self.order))
    res = BigNum.from_int(hash_bn, params.curve)
    # print("res: ", int(res))
    return res

def kdf(ecpoint, key_length):
    data = ecpoint.to_bytes()

    # TODO: Handle salt somehow
    return HKDF(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(data)