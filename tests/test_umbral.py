from cryptography.exceptions import InvalidTag
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import umbral, keys
from umbral.bignum import BigNum
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.umbral import Capsule
from collections import namedtuple


parameters = [
    # (N, M)
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
]

secp_curves = [
    ec.SECP384R1,
    ec.SECP192R1
]


TestKeyPair = namedtuple('TestKeyPair', 'priv pub')


@pytest.fixture(scope='function')
def alices_keys(curve=default_curve()):
    params = UmbralParameters(curve=curve)
    priv = keys.UmbralPrivateKey.gen_key(params)
    pub = priv.get_pubkey()
    return TestKeyPair(priv, pub)


@pytest.fixture(scope='function')
def bobs_keys(curve=default_curve()):
    params = UmbralParameters(curve=curve)
    priv = keys.UmbralPrivateKey.gen_key(params)
    pub = priv.get_pubkey()
    return TestKeyPair(priv, pub)


def test_decapsulation_by_alice(alices_keys):
    alice_priv, alice_pub = alices_keys

    sym_key, capsule = umbral._encapsulate(alice_pub.point_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.
    sym_key_2 = umbral._decapsulate_original(alice_priv.bn_key, capsule)
    assert sym_key_2 == sym_key


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(alices_keys, bobs_keys, N, M, curve=default_curve()):
    params = UmbralParameters(curve=curve)
    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    plain_data = b'attack at dawn'
    ciphertext, capsule = umbral.encrypt(pub_key_alice, plain_data)

    cleartext = umbral.decrypt(capsule, priv_key_alice, ciphertext)
    assert cleartext == plain_data

    rekeys, _unused_vkeys = umbral.split_rekey(priv_key_alice, pub_key_bob, M, N, params)
    for rekey in rekeys:
        c_frag = umbral.reencrypt(rekey, capsule)
        capsule.attach_cfrag(c_frag)

    reenc_cleartext = umbral.decrypt(
        capsule, priv_key_bob, ciphertext, pub_key_alice,
    )
    assert reenc_cleartext == plain_data


@pytest.mark.xfail(raises=umbral.GenericUmbralError)    # remove this mark to fail instead of ignore
@pytest.mark.parametrize("curve", secp_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(alices_keys, bobs_keys, N, M, curve):
    test_simple_api(alices_keys, bobs_keys, N, M, curve)


def test_pub_key_encryption(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys
    plain_data = b'attack at dawn'
    ciphertext, capsule = umbral.encrypt(pub_key_alice, plain_data)
    cleartext = umbral.decrypt(capsule, priv_key_alice, ciphertext)
    assert cleartext == plain_data


def test_bad_capsule_fails_reencryption(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    k_frags, _unused_vkeys = umbral.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    bollocks_capsule = Capsule(point_eph_e=Point.gen_rand(),
                               point_eph_v=Point.gen_rand(),
                               bn_sig=BigNum.gen_rand())

    with pytest.raises(Capsule.NotValid):
        umbral.reencrypt(k_frags[0], bollocks_capsule)


def test_two_unequal_capsules():
    one_capsule = Capsule(point_eph_e=Point.gen_rand(),
                          point_eph_v=Point.gen_rand(),
                          bn_sig=BigNum.gen_rand()
                          )

    another_capsule = Capsule(point_eph_e=Point.gen_rand(),
                              point_eph_v=Point.gen_rand(),
                              bn_sig=BigNum.gen_rand()
                              )

    assert one_capsule != another_capsule

    activated_capsule = Capsule(e_prime=Point.gen_rand(),
                                v_prime=Point.gen_rand(),
                                noninteractive_point=Point.gen_rand())

    assert activated_capsule != one_capsule


@pytest.mark.parametrize("N, M", parameters)
def test_m_of_n(N, M, alices_keys, bobs_keys):
    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    sym_key, capsule = umbral._encapsulate(pub_key_alice.point_key)
    kfrags, vkeys = umbral.split_rekey(priv_key_alice, pub_key_bob, M, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_key_alice.point_key, pub_key_bob.point_key)
        assert kfrag.is_consistent(vkeys)

    for kfrag in kfrags[:M]:
        cfrag = umbral.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)
        ch = umbral.challenge(kfrag, capsule, cfrag)
        assert umbral.check_challenge(capsule, cfrag, ch, pub_key_alice.point_key, pub_key_bob.point_key)

    # assert capsule.is_openable_by_bob()  # TODO: Is it possible to check here if >= m cFrags have been attached?
    # capsule.open(pub_bob, priv_bob, pub_alice)

    capsule._reconstruct_shamirs_secret()
    sym_key_from_capsule = umbral.decapsulate_reencrypted(pub_key_bob.point_key,
                                                          priv_key_bob.bn_key,
                                                          pub_key_alice.point_key,
                                                          capsule)
    assert sym_key == sym_key_from_capsule


def test_kfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    kfrags, _unused_vkeys = umbral.split_rekey(priv_key_alice, pub_key_alice, 1, 2)
    kfrag_bytes = kfrags[0].to_bytes()

    # A KFrag can be represented as the 194 total bytes of two Points (33 each) and four BigNums (32 each).
    assert len(kfrag_bytes) == 33 + 33 + (32 * 4) == 194

    new_frag = umbral.KFrag.from_bytes(kfrag_bytes)
    assert new_frag.bn_id == kfrags[0].bn_id
    assert new_frag.bn_key == kfrags[0].bn_key
    assert new_frag.point_eph_ni == kfrags[0].point_eph_ni
    assert new_frag.point_commitment == kfrags[0].point_commitment
    assert new_frag.bn_sig1 == kfrags[0].bn_sig1
    assert new_frag.bn_sig2 == kfrags[0].bn_sig2


def test_cfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = umbral._encapsulate(pub_key_alice.point_key)
    k_frags, _unused_vkeys = umbral.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    c_frag = umbral.reencrypt(k_frags[0], capsule)
    c_frag_bytes = c_frag.to_bytes()

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    assert len(c_frag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = umbral.CapsuleFrag.from_bytes(c_frag_bytes)
    assert new_cfrag.point_eph_e1 == c_frag.point_eph_e1
    assert new_cfrag.point_eph_v1 == c_frag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == c_frag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == c_frag.point_eph_ni


def test_capsule_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _symmetric_key, capsule = umbral._encapsulate(pub_key_alice.point_key)
    capsule_bytes = capsule.to_bytes()

    # A Capsule can be represented as the 98 total bytes of two Points (33 each) and a BigNum (32).
    assert len(capsule_bytes) == 33 + 33 + 32 == 98

    new_capsule = umbral.Capsule.from_bytes(capsule_bytes)

    # Three ways to think about equality.
    # First, the public approach for the Capsule.  Simply:
    assert new_capsule == capsule

    # Second, we show that the original components (which is all we have here since we haven't activated) are the same:
    assert new_capsule.original_components() == capsule.original_components()

    # Third, we can directly compare the private original component attributes
    # (though this is not a supported approach):
    assert new_capsule._point_eph_e == capsule._point_eph_e
    assert new_capsule._point_eph_v == capsule._point_eph_v
    assert new_capsule._bn_sig == capsule._bn_sig


def test_activated_capsule_serialization():
    priv_key = umbral.gen_priv()
    pub_key = umbral.priv2pub(priv_key)

    _unused_key, capsule = umbral._encapsulate(pub_key)
    kfrags, _unused_vkeys = umbral.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = umbral.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)

    capsule._reconstruct_shamirs_secret()
    rec_capsule_bytes = capsule.to_bytes()

    # An activated Capsule is:
    # three points, representable as 33 bytes each (the original), and
    # two points and a bignum (32 bytes) (the activated components), for 197 total.
    assert len(rec_capsule_bytes) == (33 * 3) + (33 + 33 + 32)

    new_rec_capsule = umbral.Capsule.from_bytes(rec_capsule_bytes)

    # Again, the same three perspectives on equality. 
    assert new_rec_capsule == capsule

    assert new_rec_capsule.activated_components() == capsule.activated_components()

    assert new_rec_capsule._point_eph_e_prime == capsule._point_eph_e_prime
    assert new_rec_capsule._point_eph_v_prime == capsule._point_eph_v_prime
    assert new_rec_capsule._point_noninteractive == capsule._point_noninteractive


def test_challenge_response_serialization():
    priv_key = umbral.gen_priv()
    pub_key = umbral.priv2pub(priv_key)

    _unused_key, capsule = umbral._encapsulate(pub_key)
    kfrags, _unused_vkeys = umbral.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = umbral.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)
    ch_resp = umbral.challenge(kfrags[0], capsule, cfrag)

    ch_resp_bytes = ch_resp.to_bytes()

    # A ChallengeResponse can be represented as
    # the 228 total bytes of four Points (33 each) and three BigNums (32 each).
    assert len(ch_resp_bytes) == (33 * 4) + (32 * 3) == 228

    new_ch_resp = umbral.ChallengeResponse.from_bytes(ch_resp_bytes)
    assert new_ch_resp.point_eph_e2 == ch_resp.point_eph_e2
    assert new_ch_resp.point_eph_v2 == ch_resp.point_eph_v2
    assert new_ch_resp.point_kfrag_commitment == ch_resp.point_kfrag_commitment
    assert new_ch_resp.point_kfrag_pok == ch_resp.point_kfrag_pok
    assert new_ch_resp.bn_kfrag_sig1 == ch_resp.bn_kfrag_sig1
    assert new_ch_resp.bn_kfrag_sig2 == ch_resp.bn_kfrag_sig2
    assert new_ch_resp.bn_sig == ch_resp.bn_sig


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_replays_old_reencryption(N, M, curve=default_curve()):

    params = UmbralParameters(curve=curve)

    priv_key_alice = keys.UmbralPrivateKey.gen_key(params)
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key(params)
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key_alice1, capsule_alice1 = umbral._encapsulate(pub_key_alice.point_key, params=params)
    sym_key_alice2, capsule_alice2 = umbral._encapsulate(pub_key_alice.point_key, params=params)

    k_frags, v_keys = umbral.split_rekey(priv_key_alice, pub_key_bob, M, N, params)

    for k_frag in k_frags:
        assert k_frag.is_consistent(v_keys)

    c_frags, challenges = [], []
    for index, k_frag in enumerate(k_frags):
        if index == 0:
            # Let's put the re-encryption of a different Alice ciphertext
            c_frag = umbral.reencrypt(k_frag, capsule_alice2)
        else:
            c_frag = umbral.reencrypt(k_frag, capsule_alice1)

        challenge = umbral.challenge(k_frag, capsule_alice1, c_frag)
        capsule_alice1.attach_cfrag(c_frag)

        challenges.append(challenge)
        c_frags.append(c_frag)

    capsule_alice1._reconstruct_shamirs_secret()    # activate capsule

    with pytest.raises(umbral.GenericUmbralError):
        sym_key = umbral.decapsulate_reencrypted(pub_key_bob.point_key,
                                                  priv_key_bob.bn_key,
                                                  pub_key_alice.point_key,
                                                  capsule_alice1)
        assert not sym_key == sym_key_alice1

        assert not umbral.check_challenge(capsule_alice1,
                                          c_frags[0],
                                          challenges[0],
                                          pub_key_alice.point_key,
                                          pub_key_bob.point_key,
                                          params=params)

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for (c_frag, ch) in zip(c_frags[1:], challenges[1:]):
            assert umbral.check_challenge(capsule_alice1,
                                          c_frag,
                                          ch,
                                          pub_key_alice.point_key,
                                          pub_key_bob.point_key,
                                          params=params)


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_sends_garbage(N, M, curve=default_curve()):
    params = UmbralParameters(curve=curve)

    # Alice
    priv_key_alice = keys.UmbralPrivateKey.gen_key(params)
    pub_key_alice = priv_key_alice.get_pubkey()

    # Bob
    priv_key_bob = keys.UmbralPrivateKey.gen_key(params)
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key, capsule_alice = umbral._encapsulate(pub_key_alice.point_key, params=params)
    k_frags, v_keys = umbral.split_rekey(priv_key_alice, pub_key_bob, M, N, params)

    for k_frag in k_frags:
        assert k_frag.is_consistent(v_keys)

    c_frags, challenges = [], []
    for k_frag in k_frags[0:M]:
        c_frag = umbral.reencrypt(k_frag, capsule_alice)
        challenge = umbral.challenge(k_frag, capsule_alice, c_frag)
        capsule_alice.attach_cfrag(c_frag)

        assert umbral.check_challenge(capsule_alice,
                                      c_frag,
                                      challenge,
                                      pub_key_alice.point_key,
                                      pub_key_bob.point_key,
                                      params=params)

        c_frags.append(c_frag)
        challenges.append(challenge)

    # Let's put random garbage in one of the c_frags
    c_frags[0].point_eph_e1 = Point.gen_rand()
    c_frags[0].point_eph_v1 = Point.gen_rand()

    capsule_alice._reconstruct_shamirs_secret()    # activate capsule

    with pytest.raises(umbral.GenericUmbralError):
        sym_key2 = umbral.decapsulate_reencrypted(pub_key_bob.point_key,
                                                  priv_key_bob.bn_key,
                                                  pub_key_alice.point_key,
                                                  capsule_alice)
        assert sym_key2 != sym_key
        assert not umbral.check_challenge(capsule_alice, c_frags[0], challenges[0], pub_key_alice.point_key, pub_key_bob.point_key, params=params)

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for (c_frag, ch) in zip(c_frags[1:], challenges[1:]):
            assert umbral.check_challenge(capsule_alice, c_frag, ch, pub_key_alice.point_key, pub_key_bob.point_key, params=params)


@pytest.mark.parametrize("N, M", parameters)
def test_alice_sends_fake_kfrag_to_ursula(N, M, curve=default_curve()):

    params = UmbralParameters(curve=curve)

    priv_key_alice = keys.UmbralPrivateKey.gen_key(params)
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key(params)
    pub_key_bob = priv_key_bob.get_pubkey()

    plaintext = b'attack at dawn'
    ciphertext, capsule = umbral.encrypt(pub_key_alice, plaintext)

    cleartext = umbral.decrypt(capsule, priv_key_alice, ciphertext)
    assert cleartext == plaintext

    k_frags, vkeys = umbral.split_rekey(priv_key_alice, pub_key_bob, M, N, params)

    # Alice tries to frame the first Ursula by sending her a random kFrag
    k_frags[0].bn_key = BigNum.gen_rand(curve=curve)

    for k_frag in k_frags:
        c_frag = umbral.reencrypt(k_frag, capsule)
        capsule.attach_cfrag(c_frag)

    with pytest.raises(Exception):
        _ = umbral.decrypt(capsule, priv_key_bob, ciphertext, pub_key_alice)
