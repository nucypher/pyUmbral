from . import openssl

# Global Curve Instances

SECP256R1 = openssl.Curve.from_name('secp256r1')
SECP256K1 = openssl.Curve.from_name('secp256k1')
SECP384R1 = openssl.Curve.from_name('secp384r1')

CURVES = (SECP256K1, SECP256R1, SECP384R1)

CURVE = SECP256K1
