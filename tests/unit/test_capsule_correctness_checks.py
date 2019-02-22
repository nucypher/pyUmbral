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

import os

import pytest

from umbral.curvebn import CurveBN
from umbral.cfrags import CapsuleFrag
from umbral.keys import UmbralPrivateKey
from umbral.point import Point
from umbral.pre import Capsule
from umbral.config import default_params


def test_cannot_attach_cfrag_without_keys():
    """
    We need the proper keys to verify the correctness of CFrags
    in order to attach them to a Capsule.
    """
    params = default_params()

    capsule = Capsule(params,
                      point_e=Point.gen_rand(),
                      point_v=Point.gen_rand(),
                      bn_sig=CurveBN.gen_rand())

    cfrag = CapsuleFrag(point_e1=Point.gen_rand(),
                        point_v1=Point.gen_rand(),
                        kfrag_id=os.urandom(10),
                        point_precursor=Point.gen_rand(),
                        )

    with pytest.raises(TypeError):
        capsule.attach_cfrag(cfrag)


def test_cannot_attach_cfrag_without_proof():
    """
    However, even when properly attaching keys, we can't attach the CFrag
    if it is unproven.
    """
    params = default_params()

    capsule = Capsule(params,
                      point_e=Point.gen_rand(),
                      point_v=Point.gen_rand(),
                      bn_sig=CurveBN.gen_rand())

    cfrag = CapsuleFrag(point_e1=Point.gen_rand(),
                        point_v1=Point.gen_rand(),
                        kfrag_id=os.urandom(10),
                        point_precursor=Point.gen_rand(),
                        )
    key_details = capsule.set_correctness_keys(
        UmbralPrivateKey.gen_key().get_pubkey(),
        UmbralPrivateKey.gen_key().get_pubkey(),
        UmbralPrivateKey.gen_key().get_pubkey())

    delegating_details, receiving_details, verifying_details = key_details

    assert all((delegating_details, receiving_details, verifying_details))

    with pytest.raises(cfrag.NoProofProvided):
        capsule.attach_cfrag(cfrag)


def test_cannot_set_different_keys():
    """
    Once a key is set on a Capsule, it can't be changed to a different key.
    """
    params = default_params()

    capsule = Capsule(params,
                      point_e=Point.gen_rand(),
                      point_v=Point.gen_rand(),
                      bn_sig=CurveBN.gen_rand())

    capsule.set_correctness_keys(delegating=UmbralPrivateKey.gen_key().get_pubkey(),
                                 receiving=UmbralPrivateKey.gen_key().get_pubkey(),
                                 verifying=UmbralPrivateKey.gen_key().get_pubkey())

    with pytest.raises(ValueError):
        capsule.set_correctness_keys(delegating=UmbralPrivateKey.gen_key().get_pubkey())

    with pytest.raises(ValueError):
        capsule.set_correctness_keys(receiving=UmbralPrivateKey.gen_key().get_pubkey())

    with pytest.raises(ValueError):
        capsule.set_correctness_keys(verifying=UmbralPrivateKey.gen_key().get_pubkey())
