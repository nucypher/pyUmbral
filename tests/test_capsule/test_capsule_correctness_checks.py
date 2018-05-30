import os

import pytest

from umbral.curvebn import CurveBN
from umbral.fragments import CapsuleFrag
from umbral.keys import UmbralPrivateKey
from umbral.point import Point
from umbral.pre import Capsule


def test_cannot_attach_cfrag_without_proof():
    capsule = Capsule(point_e=Point.gen_rand(),
                      point_v=Point.gen_rand(),
                      bn_sig=CurveBN.gen_rand())

    cfrag = CapsuleFrag(point_e1=Point.gen_rand(),
                        point_v1=Point.gen_rand(),
                        kfrag_id=os.urandom(10),
                        point_noninteractive=Point.gen_rand(),
                        point_xcoord=Point.gen_rand(),
                        )
    key_details = capsule.get_or_set_three_keys(
        UmbralPrivateKey.gen_key().get_pubkey(),
        UmbralPrivateKey.gen_key().get_pubkey(),
        UmbralPrivateKey.gen_key().get_pubkey())

    delegating_details, encrypting_details, verifying_details = key_details

    assert all((delegating_details[1], encrypting_details[1], verifying_details[1]))

    with pytest.raises(cfrag.NoProofProvided):
        capsule.attach_cfrag(cfrag)
