"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

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

