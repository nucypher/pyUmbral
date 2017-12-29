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

def test_invalid_points():
    curve = ec.SECP256K1()
    p = Point.gen_rand(curve)

    pbytes = bytearray(p.to_bytes(is_compressed=False))
    # Flips last bit
    pbytes[-1] = pbytes[-1] ^ 0x01
    pbytes = bytes(pbytes)

    try:
    	q = Point.from_bytes(pbytes, curve)
    	assert False
    except:
    	pass

