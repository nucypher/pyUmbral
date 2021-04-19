from . import openssl

SECP256K1 = openssl.Curve.from_name('secp256k1')

CURVE = SECP256K1
