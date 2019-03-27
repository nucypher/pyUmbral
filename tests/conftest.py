"""
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

kfrag_signing_modes = (
    (True, True), (True, False), (False, True), (False, False)
)


@pytest.fixture
def alices_keys():
    delegating_priv = keys.UmbralPrivateKey.gen_key()
    signing_priv = keys.UmbralPrivateKey.gen_key()
    return delegating_priv, signing_priv


@pytest.fixture
def bobs_keys():
    priv = keys.UmbralPrivateKey.gen_key()
    pub = priv.get_pubkey()
    return priv, pub


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




@pytest.fixture(scope='session')
def message():
    message = b"dnunez [9:30 AM]" \
              b"@Tux we had this super fruitful discussion last night with @jMyles @michwill @KPrasch" \
              b"to sum up: the symmetric ciphertext is now called the 'Chimney'." \
              b"the chimney of the capsule, of course" \
              b"tux [9:32 AM]" \
              b"wat"
    return message


@pytest.fixture
def ciphertext_and_capsule(alices_keys, message):
    delegating_privkey, _signing_privkey = alices_keys
    # See nucypher's issue #183
    chimney, capsule = pre.encrypt(delegating_privkey.get_pubkey(), message)
    return chimney, capsule


@pytest.fixture
def capsule(ciphertext_and_capsule):
    ciphertext, capsule = ciphertext_and_capsule
    return capsule


@pytest.fixture
def prepared_capsule(alices_keys, bobs_keys, capsule):
    delegating_privkey, signing_privkey = alices_keys
    _receiving_privkey, receiving_pubkey = bobs_keys
    capsule.set_correctness_keys(delegating=delegating_privkey.get_pubkey(),
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())
    return capsule    


@pytest.fixture
def kfrags(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    signer_alice = Signer(signing_privkey)

    receiving_privkey, receiving_pubkey = bobs_keys

    yield pre.generate_kfrags(delegating_privkey=delegating_privkey,
                              signer=signer_alice,
                              receiving_pubkey=receiving_pubkey,
                              threshold=6, N=10)
