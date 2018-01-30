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
 
    res = BigNum.from_int(hash_bn, params.curve)
 
    return res

def hash_to_point(curve, data, constant=None):
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.
    It admits an optional constant as an additional input to the hash function.
    It uses SHA256 as the internal hash function. 

    WARNING: Do not use when the input data is secret, as this implementation is not 
    in constant time, and hence, it is not safe with respect to timing attacks.

    TODO: Check how to uniformly generate ycoords. Currently, it only outputs points 
    where ycoord is even (i.e., starting with 0x02 in compressed notation)
    """
    if constant is None:
        constant = []

    # We use a 32-bit counter as additional input
    i = 1
    while i < 2**32:
        ibytes = i.to_bytes(4, byteorder='big')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(constant + ibytes + data)
        hash = digest.finalize()

        compressed02 = b"\x02"+hash
        try:
            h = Point.from_bytes(compressed02, curve)
            return h
        except:
            pass

        i+=1

    # Only happens with probability 2^(-32)
    raise ValueError('Could not find %c in %s' % (ch,str))

def kdf(ecpoint, key_length):
    data = ecpoint.to_bytes(is_compressed=True)

    return HKDF(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(data)
