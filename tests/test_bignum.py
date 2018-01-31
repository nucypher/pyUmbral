from umbral.bignum import BigNum
from cryptography.hazmat.primitives.asymmetric import ec

def test_from_to_int():
    curve = ec.SECP256K1()
    x = BigNum.gen_rand(curve)

    xint = x.__int__()
    
    y = BigNum.from_int(xint, curve)

    assert x == y