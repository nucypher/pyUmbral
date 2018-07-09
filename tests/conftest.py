import pytest
from collections import namedtuple

from umbral import keys
from umbral.curve import SECP256K1
from umbral.curvebn import CurveBN
from umbral.config import set_default_curve
from umbral.point import Point

set_default_curve(SECP256K1)


MockKeyPair = namedtuple('TestKeyPair', 'priv pub')


parameters = [
    # (N, M)
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
]

wrong_parameters = [
    # (N, M)
    (-1, -1),   (-1, 0),    (-1, 5),
    (0, -1),    (0, 0),     (0, 5),
    (1, -1),    (1, 0),     (1, 5),
    (5, -1),    (5, 0),     (5, 10)
]

@pytest.fixture(scope='function')
def alices_keys():
    delegating_priv = keys.UmbralPrivateKey.gen_key()
    signing_priv = keys.UmbralPrivateKey.gen_key()
    return delegating_priv, signing_priv


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
def random_ec_curvebn1():
    yield CurveBN.gen_rand()


@pytest.fixture()
def random_ec_curvebn2():
    yield CurveBN.gen_rand()

