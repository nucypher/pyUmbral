from umbral.bignum import BigNum
from cryptography.hazmat.primitives.asymmetric import ec
from umbral.config import default_curve



def test_from_to_int():
    curve = default_curve() or ec.SECP256K1()
    x = BigNum.gen_rand(curve)

    xint = x.__int__()
    
    y = BigNum.from_int(xint, curve)

    assert x == y


def test_bn_to_cryptography_privkey():
    curve = ec.SECP256K1()
    bn = BigNum.gen_rand(curve)

    crypto_privkey = bn.to_cryptography_priv_key()

    assert int(bn) == crypto_privkey.private_numbers().private_value 
