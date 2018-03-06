import pytest

from umbral import pre, keys
from umbral.point import Point
from .conftest import parameters


def test_challenge_response_serialization():
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _unused_key, capsule = pre._encapsulate(pub_key)
    kfrags = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)
    ch_resp = pre.challenge(kfrags[0], capsule, cfrag)

    ch_resp_bytes = ch_resp.to_bytes()

    # A ChallengeResponse can be represented as
    # the 228 total bytes of four Points (33 each) and three BigNums (32 each).
    assert len(ch_resp_bytes) == (33 * 4) + (32 * 3) == 228

    new_ch_resp = pre.ChallengeResponse.from_bytes(ch_resp_bytes)
    assert new_ch_resp.point_eph_e2 == ch_resp.point_eph_e2
    assert new_ch_resp.point_eph_v2 == ch_resp.point_eph_v2
    assert new_ch_resp.point_kfrag_commitment == ch_resp.point_kfrag_commitment
    assert new_ch_resp.point_kfrag_pok == ch_resp.point_kfrag_pok
    assert new_ch_resp.bn_kfrag_sig1 == ch_resp.bn_kfrag_sig1
    assert new_ch_resp.bn_kfrag_sig2 == ch_resp.bn_kfrag_sig2
    assert new_ch_resp.bn_sig == ch_resp.bn_sig


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_replays_old_reencryption(N, M):
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key_alice1, capsule_alice1 = pre._encapsulate(pub_key_alice.point_key)
    sym_key_alice2, capsule_alice2 = pre._encapsulate(pub_key_alice.point_key)

    k_frags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    c_frags, challenges = [], []
    for index, k_frag in enumerate(k_frags):
        if index == 0:
            # Let's put the re-encryption of a different Alice ciphertext
            c_frag = pre.reencrypt(k_frag, capsule_alice2)
        else:
            c_frag = pre.reencrypt(k_frag, capsule_alice1)

        challenge = pre.challenge(k_frag, capsule_alice1, c_frag)
        capsule_alice1.attach_cfrag(c_frag)

        challenges.append(challenge)
        c_frags.append(c_frag)

    capsule_alice1._reconstruct_shamirs_secret()    # activate capsule

    with pytest.raises(pre.GenericUmbralError):
        sym_key = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                              priv_key_bob.bn_key,
                                              pub_key_alice.point_key,
                                              capsule_alice1)
        assert not sym_key == sym_key_alice1

        assert not pre.check_challenge(capsule_alice1,
                                       c_frags[0],
                                       challenges[0],
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                       )

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for (c_frag, ch) in zip(c_frags[1:], challenges[1:]):
            assert pre.check_challenge(capsule_alice1,
                                       c_frag,
                                       ch,
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                       )


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_sends_garbage(N, M):
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    # Bob
    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key, capsule_alice = pre._encapsulate(pub_key_alice.point_key)
    k_frags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    c_frags, challenges = [], []
    for k_frag in k_frags[0:M]:
        c_frag = pre.reencrypt(k_frag, capsule_alice)
        challenge = pre.challenge(k_frag, capsule_alice, c_frag)
        capsule_alice.attach_cfrag(c_frag)

        assert pre.check_challenge(capsule_alice,
                                   c_frag,
                                   challenge,
                                   pub_key_alice.point_key,
                                   pub_key_bob.point_key,
                                   )

        c_frags.append(c_frag)
        challenges.append(challenge)

    # Let's put random garbage in one of the c_frags
    c_frags[0].point_eph_e1 = Point.gen_rand()
    c_frags[0].point_eph_v1 = Point.gen_rand()

    capsule_alice._reconstruct_shamirs_secret()    # activate capsule

    with pytest.raises(pre.GenericUmbralError):
        sym_key2 = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                               priv_key_bob.bn_key,
                                               pub_key_alice.point_key,
                                               capsule_alice)
        assert sym_key2 != sym_key
        assert not pre.check_challenge(capsule_alice, c_frags[0], challenges[0], pub_key_alice.point_key, pub_key_bob.point_key)

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for (c_frag, ch) in zip(c_frags[1:], challenges[1:]):
            assert pre.check_challenge(capsule_alice, c_frag, ch, pub_key_alice.point_key, pub_key_bob.point_key)


@pytest.mark.parametrize("N, M", parameters)
def test_m_of_n(N, M, alices_keys, bobs_keys):
    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    sym_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_key_alice.point_key, pub_key_bob.point_key)

    for kfrag in kfrags[:M]:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)
        ch = pre.challenge(kfrag, capsule, cfrag)
        assert pre.check_challenge(capsule, cfrag, ch, pub_key_alice.point_key, pub_key_bob.point_key)

    # assert capsule.is_openable_by_bob()  # TODO: Is it possible to check here if >= m cFrags have been attached?
    # capsule.open(pub_bob, priv_bob, pub_alice)

    capsule._reconstruct_shamirs_secret()
    sym_key_from_capsule = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                                       priv_key_bob.bn_key,
                                                       pub_key_alice.point_key,
                                                       capsule)
    assert sym_key == sym_key_from_capsule
