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

def test_generator():
    curve = ec.SECP256K1()
    g1 = Point.get_generator_from_curve(curve)

    # http://www.secg.org/SEC2-Ver-1.0.pdf
    # Section 2.7.1
    g_compressed = 0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    g_compressed = g_compressed.to_bytes(32+1, byteorder='big')

    g_uncompressed = 0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    g_uncompressed = g_uncompressed.to_bytes(64+1, byteorder='big')

    g2 = Point.from_bytes(g_compressed, curve)
    assert g1 == g2

    g3 = Point.from_bytes(g_uncompressed, curve)
    assert g1 == g3


    assert g2 == g3