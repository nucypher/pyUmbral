import pytest

from umbral.bignum import BigNum
from umbral.config import set_default_curve, default_curve
from cryptography.hazmat.primitives.asymmetric import ec

from umbral.point import Point


secp256k1 = ec.SECP256K1()
set_default_curve(secp256k1)
curve = default_curve() or secp256k1


@pytest.fixture()
def random_ec_point1():
    yield Point.gen_rand(curve)


@pytest.fixture()
def random_ec_point2():
    yield Point.gen_rand(curve)


@pytest.fixture()
def random_ec_bignum():
    yield BigNum.gen_rand(curve)
