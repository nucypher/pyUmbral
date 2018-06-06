import os

import pytest

from umbral import pre
from umbral.curvebn import CurveBN
from umbral.fragments import CapsuleFrag
from umbral.keys import UmbralPrivateKey
from umbral.point import Point
from umbral.pre import Capsule
from umbral.signing import Signer
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
                        point_noninteractive=Point.gen_rand(),
                        point_xcoord=Point.gen_rand(),
                        )
    with pytest.raises(TypeError):
        capsule.attach_cfrag(cfrag)


def test_set_correctness_keys(alices_keys, bobs_keys):
    """
    If the three keys do appear together, along with the capsule,
    we can attach them all at once.
    """

    delegating_privkey, signing_privkey = alices_keys
    signer = Signer(signing_privkey)
    priv_key_bob, pub_key_bob = bobs_keys

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data)

    capsule.set_correctness_keys(delegating_privkey.get_pubkey(),
                     pub_key_bob,
                     signing_privkey.get_pubkey()
                     )

    kfrags = pre.split_rekey(delegating_privkey, signer, pub_key_bob, 2, 2)
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule)
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
                        point_noninteractive=Point.gen_rand(),
                        point_xcoord=Point.gen_rand(),
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
