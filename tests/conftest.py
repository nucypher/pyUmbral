import pytest
from collections import namedtuple
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import keys
from umbral.bignum import BigNum
from umbral.config import set_default_curve
from umbral.point import Point

set_default_curve(ec.SECP256K1)


MockKeyPair = namedtuple('TestKeyPair', 'priv pub')


parameters = [
    # (N, M)
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
]


@pytest.fixture(scope='function')
def alices_keys():
    priv = keys.UmbralPrivateKey.gen_key()
    pub = priv.get_pubkey()
    return MockKeyPair(priv, pub)


@pytest.fixture(scope='function')
def bobs_keys():
    priv = keys.UmbralPrivateKey.gen_key()
    pub = priv.get_pubkey()
    return MockKeyPair(priv, pub)


@pytest.fixture()
def random_ec_point1():
    yield Point.gen_rand()


@pytest.fixture()
def random_ec_point2():
    yield Point.gen_rand()


@pytest.fixture()
def random_ec_bignum1():
    yield BigNum.gen_rand()


@pytest.fixture()
def random_ec_bignum2():
    yield BigNum.gen_rand()

