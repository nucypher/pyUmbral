from umbral.point import Point
from umbral.bignum import BigNum
from cryptography.hazmat.primitives.asymmetric import ec

def test_from_to_bytes():
    curve = ec.SECP256K1()
    p = Point.gen_rand(curve)

    pbytes = p.to_bytes(is_compressed=False)
    q = Point.from_bytes(pbytes, curve)

    assert p == q

    pbytes = p.to_bytes(is_compressed=True)
    q = Point.from_bytes(pbytes, curve)

    assert p == q
