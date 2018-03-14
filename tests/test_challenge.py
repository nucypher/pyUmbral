import pytest

from umbral import pre, keys
from umbral.point import Point
from .conftest import parameters


def test_challenge_response_serialization():
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)

    metadata = b"Challenge metadata"
    ch_resp = pre.challenge(kfrags[0], capsule, cfrag, metadata)

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

        metadata = ("Challenge metadata: index {}".format(index)).encode()

        challenge = pre.challenge(k_frag, capsule_alice1, c_frag, metadata)
        capsule_alice1.attach_cfrag(c_frag)

        challenges.append(challenge)
        c_frags.append(c_frag)

    # Let's activate the capsule
    capsule_alice1._reconstruct_shamirs_secret(pub_key_alice, priv_key_bob)    

    with pytest.raises(pre.GenericUmbralError):
        sym_key = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                              priv_key_bob.bn_key,
                                              pub_key_alice.point_key,
                                              capsule_alice1)
        assert not sym_key == sym_key_alice1

        metadata = b"Challenge metadata: index 0"

        assert not pre.check_challenge(capsule_alice1,
                                       c_frags[0],
                                       challenges[0],
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                       metadata
                                       )

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for i, challenge in enumerate(challenges, 1):
            c_frag = c_frags[i]
            metadata = ("Challenge metadata: index {}".format(i)).encode()
            assert pre.check_challenge(capsule_alice1,
                                       c_frag,
                                       ch,
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                       metadata
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
    for i, k_frag in enumerate(k_frags[:M]):
        c_frag = pre.reencrypt(k_frag, capsule_alice)
        metadata = ("Challenge metadata: index {}".format(i)).encode()
        challenge = pre.challenge(k_frag, capsule_alice, c_frag, metadata)
        capsule_alice.attach_cfrag(c_frag)

        assert pre.check_challenge(capsule_alice,
                                   c_frag,
                                   challenge,
                                   pub_key_alice.point_key,
                                   pub_key_bob.point_key,
                                   metadata
                                   )

        c_frags.append(c_frag)
        challenges.append(challenge)

    # Let's put random garbage in one of the c_frags
    c_frags[0].point_eph_e1 = Point.gen_rand()
    c_frags[0].point_eph_v1 = Point.gen_rand()

    capsule_alice._reconstruct_shamirs_secret(pub_key_alice, priv_key_bob)    # activate capsule

    with pytest.raises(pre.GenericUmbralError):
        sym_key2 = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                               priv_key_bob.bn_key,
                                               pub_key_alice.point_key,
                                               capsule_alice)
        assert sym_key2 != sym_key
        metadata = b"Challenge metadata: index 0"
        assert not pre.check_challenge(capsule_alice, 
                                       c_frags[0], 
                                       challenges[0], 
                                       pub_key_alice.point_key, 
                                       pub_key_bob.point_key,
                                       metadata
                                       )

        # The response of cheating Ursula is in capsules[0],
        # so the rest of challenges chould be correct:
        for i, challenge in enumerate(challenges, 1):
            c_frag = c_frags[i]
            metadata = ("Challenge metadata: index {}".format(i)).encode()
            assert pre.check_challenge(capsule_alice, 
                                       c_frag, 
                                       ch, 
                                       pub_key_alice.point_key, 
                                       pub_key_bob.point_key,
                                       metadata
                                       )


@pytest.mark.parametrize("N, M", parameters)
def test_m_of_n(N, M, alices_keys, bobs_keys):
    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    sym_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_key_alice.point_key, pub_key_bob.point_key)

    for i, kfrag in enumerate(kfrags[:M]):
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)
        metadata = ("Challenge metadata: index {}".format(i)).encode()
        ch = pre.challenge(kfrag, capsule, cfrag, metadata)

        assert pre.check_challenge(capsule, 
                                   cfrag, 
                                   ch, 
                                   pub_key_alice.point_key, 
                                   pub_key_bob.point_key,
                                   metadata
                                   )

    # assert capsule.is_openable_by_bob()  # TODO: Is it possible to check here if >= m cFrags have been attached?
    # capsule.open(pub_bob, priv_bob, pub_alice)

    capsule._reconstruct_shamirs_secret(pub_key_alice, priv_key_bob)
    sym_key_from_capsule = pre.decapsulate_reencrypted(pub_key_bob.point_key,
                                                       priv_key_bob.bn_key,
                                                       pub_key_alice.point_key,
                                                       capsule)
    assert sym_key == sym_key_from_capsule
