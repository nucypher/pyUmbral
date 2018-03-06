import pytest

from umbral import pre, keys
from umbral.bignum import BigNum
from umbral.point import Point
from umbral.pre import Capsule
from tests.conftest import parameters


def test_capsule_creation(alices_keys):
    with pytest.raises(TypeError):
        rare_capsule = Capsule()    # Alice cannot make a capsule this way.

    # Some users may create capsules their own way.
    custom_capsule = Capsule(point_eph_e=Point.gen_rand(),
                             point_eph_v=Point.gen_rand(),
                             bn_sig=BigNum.gen_rand())

    assert isinstance(custom_capsule, Capsule)

    # Typical Alice, constructing a typical capsule
    _, alices_public_key = alices_keys
    plaintext = b'attack at dawn'
    ciphertext, typical_capsule = pre.encrypt(alices_public_key, plaintext)

    assert isinstance(typical_capsule, Capsule)


def test_capsule_equality():
    one_capsule = Capsule(point_eph_e=Point.gen_rand(),
                          point_eph_v=Point.gen_rand(),
                          bn_sig=BigNum.gen_rand())

    another_capsule = Capsule(point_eph_e=Point.gen_rand(),
                              point_eph_v=Point.gen_rand(),
                              bn_sig=BigNum.gen_rand())

    assert one_capsule != another_capsule

    activated_capsule = Capsule(e_prime=Point.gen_rand(),
                                v_prime=Point.gen_rand(),
                                noninteractive_point=Point.gen_rand())

    assert activated_capsule != one_capsule


def test_decapsulation_by_alice(alices_keys):
    alice_priv, alice_pub = alices_keys

    sym_key, capsule = pre._encapsulate(alice_pub.point_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.
    sym_key_2 = pre._decapsulate_original(alice_priv.bn_key, capsule)
    assert sym_key_2 == sym_key


def test_bad_capsule_fails_reencryption(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    bollocks_capsule = Capsule(point_eph_e=Point.gen_rand(),
                               point_eph_v=Point.gen_rand(),
                               bn_sig=BigNum.gen_rand())

    with pytest.raises(Capsule.NotValid):
        pre.reencrypt(kfrags[0], bollocks_capsule)


def test_capsule_as_dict_key(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys
    plain_data = b'attack at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice, plain_data)

    # We can use the capsule as a key, and successfully lookup using it.
    some_dict = {capsule: "Thing that Bob wants to try per-Capsule"}
    assert some_dict[capsule] == "Thing that Bob wants to try per-Capsule"

    kfrags = pre.split_rekey(alices_keys.priv, alices_keys.pub, 1, 2)
    cfrag = pre.reencrypt(kfrags[0], capsule)
    capsule.attach_cfrag(cfrag)

    cfrag = pre.reencrypt(kfrags[1], capsule)
    capsule.attach_cfrag(cfrag)

    # Even if we activate the capsule, it still serves as the same key.
    cleartext = pre.decrypt(capsule, alices_keys.priv, ciphertext, alices_keys.pub)
    assert some_dict[capsule] == "Thing that Bob wants to try per-Capsule"
    assert cleartext == plain_data

    # And if we change the value for this key, all is still well.
    some_dict[capsule] = "Bob has changed his mind."
    assert some_dict[capsule] == "Bob has changed his mind."
    assert len(some_dict.keys()) == 1


@pytest.mark.parametrize("N, M", parameters)
def test_alice_sends_fake_kfrag_to_ursula(N, M):

    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    plaintext = b'attack at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice, plaintext)

    cleartext = pre.decrypt(capsule, priv_key_alice, ciphertext)
    assert cleartext == plaintext

    k_frags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    # Alice tries to frame the first Ursula by sending her a random kFrag
    k_frags[0].bn_key = BigNum.gen_rand()

    for k_frag in k_frags:
        c_frag = pre.reencrypt(k_frag, capsule)
        capsule.attach_cfrag(c_frag)

    with pytest.raises(Exception):
        _ = pre.decrypt(capsule, priv_key_bob, ciphertext, pub_key_alice)
