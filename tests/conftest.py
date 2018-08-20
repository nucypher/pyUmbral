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
from umbral.curve import SECP256K1, SECP384R1, SECP256R1
from umbral.curvebn import CurveBN
from umbral.config import set_default_curve
from umbral.point import Point
from umbral.signing import Signer
from umbral import pre

set_default_curve(SECP256K1)

MockKeyPair = namedtuple('TestKeyPair', 'priv pub')

parameters = (
    # (N, M)
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
)

wrong_parameters = (
    # (N, M)
    (-1, -1),   (-1, 0),    (-1, 5),
    (0, -1),    (0, 0),     (0, 5),
    (1, -1),    (1, 0),     (1, 5),
    (5, -1),    (5, 0),     (5, 10)
)

other_supported_curves = (
    SECP384R1,
    SECP256R1
)

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


@pytest.fixture(scope='function')
def capsule(alices_keys):
    delegating_privkey, _signing_privkey = alices_keys
    _sym_key, capsule = pre._encapsulate(delegating_privkey.get_pubkey())
    return capsule   

@pytest.fixture
def prepared_capsule(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    _receiving_privkey, receiving_pubkey = bobs_keys

    _sym_key, capsule = pre._encapsulate(delegating_privkey.get_pubkey())
    capsule.set_correctness_keys(delegating=delegating_privkey.get_pubkey(),
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())
    return capsule    

@pytest.fixture(scope='function')
def kfrags(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()
    signer_alice = Signer(signing_privkey)

    receiving_privkey, receiving_pubkey = bobs_keys

    yield pre.split_rekey(delegating_privkey, signer_alice, receiving_pubkey, 6, 10)




