from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InternalError

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


def hash_to_bn(crypto_items, params):
    sha_512 = hashes.Hash(hashes.SHA512(), backend=default_backend())
    for item in crypto_items:
        if isinstance(item, Point):
            data_bytes = item.to_bytes()
        elif isinstance(item, BigNum):
            data_bytes = int(item).to_bytes(params.CURVE_KEY_SIZE_BYTES, 'big')
        else:
            data_bytes = item
        sha_512.update(data_bytes)

    i = 0
    h = 0
    while h < params.CURVE_MINVAL_SHA512:
        sha_512_i = sha_512.copy()
        sha_512_i.update(i.to_bytes(params.CURVE_KEY_SIZE_BYTES, 'big'))
        hash_digest = sha_512_i.finalize()
        h = int.from_bytes(hash_digest, byteorder='big', signed=False)
        i += 1
    hash_bn = h % int(params.order)
 
    res = BigNum.from_int(hash_bn, params.curve)
 
    return res

def unsafe_hash_to_point(params, data, label=None):
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.
    It admits an optional label as an additional input to the hash function.
    It uses SHA256 as the internal hash function. 

    WARNING: Do not use when the input data is secret, as this implementation is not 
    in label time, and hence, it is not safe with respect to timing attacks.

    TODO: Check how to uniformly generate ycoords. Currently, it only outputs points 
    where ycoord is even (i.e., starting with 0x02 in compressed notation)
    """
    if label is None:
        label = []

    # We use a 32-bit counter as additional input
    i = 1
    while i < 2**32:
        ibytes = i.to_bytes(4, byteorder='big')
        sha_512 = hashes.Hash(hashes.SHA512(), backend=default_backend())
        sha_512.update(label + ibytes + data)
        hash_digest = sha_512.finalize()[:params.CURVE_KEY_SIZE_BYTES]

        compressed02 = b"\x02" + hash_digest

        try:
            h = Point.from_bytes(compressed02, params.curve)
            return h
        except InternalError as e:
            # We want to catch specific InternalExceptions: 
            # - Point not in the curve (code 107)
            # - Invalid compressed point (code 110)
            # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
            if e.err_code[0].reason in (107, 110):
                pass
            else:
                # Any other exception, we raise it
                raise e
        
        i += 1

    # Only happens with probability 2^(-32)
    raise ValueError('Could not hash input into the curve')


def kdf(ecpoint, key_length):
    data = ecpoint.to_bytes(is_compressed=True)

    return HKDF(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(data)
