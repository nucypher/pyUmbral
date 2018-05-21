import pytest

from umbral import pre, keys
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.pre import Capsule
from umbral.signing import Signer


def test_capsule_creation(alices_keys):
    with pytest.raises(TypeError):
        rare_capsule = Capsule()    # Alice cannot make a capsule this way.

    # Some users may create capsules their own way.
    custom_capsule = Capsule(point_e=Point.gen_rand(),
                             point_v=Point.gen_rand(),
                             bn_sig=CurveBN.gen_rand())

    assert isinstance(custom_capsule, Capsule)

    # Typical Alice, constructing a typical capsule
    _, alices_public_key = alices_keys
    plaintext = b'peace at dawn'
    ciphertext, typical_capsule = pre.encrypt(alices_public_key, plaintext)

    assert isinstance(typical_capsule, Capsule)


def test_capsule_equality():
    one_capsule = Capsule(point_e=Point.gen_rand(),
                          point_v=Point.gen_rand(),
                          bn_sig=CurveBN.gen_rand())

    another_capsule = Capsule(point_e=Point.gen_rand(),
                              point_v=Point.gen_rand(),
                              bn_sig=CurveBN.gen_rand())

    assert one_capsule != another_capsule

    activated_capsule = Capsule(point_e_prime=Point.gen_rand(),
                                point_v_prime=Point.gen_rand(),
                                point_noninteractive=Point.gen_rand())

    assert activated_capsule != one_capsule


def test_decapsulation_by_alice(alices_keys):
    alice_priv, alice_pub = alices_keys

    sym_key, capsule = pre._encapsulate(alice_pub.point_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.
    sym_key_2 = pre._decapsulate_original(alice_priv.bn_key, capsule)
    assert sym_key_2 == sym_key


def test_bad_capsule_fails_reencryption(alices_keys):
    priv_key_alice_deleg = keys.UmbralPrivateKey.gen_key()
    pub_key_alice_deleg = priv_key_alice_deleg.get_pubkey()
    priv_key_alice_sig = keys.UmbralPrivateKey.gen_key()
    pub_key_alice_sig = priv_key_alice_sig.get_pubkey()
    signer_alice = Signer(priv_key_alice_sig)


    kfrags = pre.split_rekey(priv_key_alice_deleg, signer_alice, pub_key_alice_deleg, 1, 2)

    bollocks_capsule = Capsule(point_e=Point.gen_rand(),
                               point_v=Point.gen_rand(),
                               bn_sig=CurveBN.gen_rand())

    with pytest.raises(Capsule.NotValid):
        pre.reencrypt(kfrags[0], bollocks_capsule)


def test_capsule_as_dict_key(alices_keys):
    # TODO: This test is a little weird - why activate a Capsule from alice to alice?  Let's get bob involved.
    priv_key_alice_deleg = keys.UmbralPrivateKey.gen_key()
    pub_key_alice_deleg = priv_key_alice_deleg.get_pubkey()
    priv_key_alice_sig = keys.UmbralPrivateKey.gen_key()
    pub_key_alice_sig = priv_key_alice_sig.get_pubkey()
    signer_alice = Signer(priv_key_alice_sig)

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice_deleg, plain_data)

    # We can use the capsule as a key, and successfully lookup using it.
    some_dict = {capsule: "Thing that Bob wants to try per-Capsule"}
    assert some_dict[capsule] == "Thing that Bob wants to try per-Capsule"

    kfrags = pre.split_rekey(priv_key_alice_deleg, signer_alice, pub_key_alice_deleg, 1, 2)
    cfrag = pre.reencrypt(kfrags[0], capsule)
    capsule.attach_cfrag(cfrag)

    cfrag = pre.reencrypt(kfrags[1], capsule)
    capsule.attach_cfrag(cfrag)

    # Even if we activate the capsule, it still serves as the same key.
    cleartext = pre.decrypt(ciphertext, capsule, priv_key_alice_deleg, pub_key_alice_deleg, pub_key_alice_sig)
    assert some_dict[capsule] == "Thing that Bob wants to try per-Capsule"
    assert cleartext == plain_data

    # And if we change the value for this key, all is still well.
    some_dict[capsule] = "Bob has changed his mind."
    assert some_dict[capsule] == "Bob has changed his mind."
    assert len(some_dict.keys()) == 1
