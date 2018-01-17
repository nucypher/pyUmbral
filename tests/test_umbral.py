import pytest

from umbral import umbral

# (N,threshold)
parameters = [
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
]


def test_decapsulation_by_alice():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, capsule = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.

    sym_key_2 = pre.decapsulate_original(priv_key, capsule)
    assert sym_key_2 == sym_key


@pytest.mark.parametrize("N,threshold", parameters)
def test_m_of_n(N, threshold):
    pre = umbral.PRE(umbral.UmbralParameters())
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, capsule_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_alice, pub_bob, pre.params)
        assert kfrag.is_consistent(vkeys, pre.params)

    for kfrag in kfrags[:threshold]:
        cfrag = pre.reencrypt(kfrag, capsule_alice)
        capsule_alice.attach_cfrag(cfrag)
        ch = pre.challenge(kfrag, capsule_alice, cfrag)
        assert pre.check_challenge(capsule_alice, cfrag, ch, pub_alice, pub_bob)

    capsule_bob = capsule_alice.reconstruct()

    sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule_bob, capsule_alice)

    assert sym_key_2 == sym_key


def test_kfrag_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    kfrags, _ = pre.split_rekey(priv_key, pub_key, 1, 2)
    kfrag_bytes = kfrags[0].to_bytes()

    # A KFrag can be represented as the 194 total bytes of two Points (33 each) and four BigNums (32 each).
    assert len(kfrag_bytes) == 33 + 33 + (32 * 4) == 194

    new_frag = umbral.KFrag.from_bytes(kfrag_bytes,
                                       umbral.UmbralParameters().curve)
    assert new_frag.bn_id == kfrags[0].bn_id
    assert new_frag.bn_key == kfrags[0].bn_key
    assert new_frag.point_eph_ni == kfrags[0].point_eph_ni
    assert new_frag.point_commitment == kfrags[0].point_commitment
    assert new_frag.bn_sig1 == kfrags[0].bn_sig1
    assert new_frag.bn_sig2 == kfrags[0].bn_sig2


def test_cfrag_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _, capsule = pre.encapsulate(pub_key)
    kfrags, _ = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)
    cfrag_bytes = cfrag.to_bytes()

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = umbral.CapsuleFrag.from_bytes(cfrag_bytes,
                                              umbral.UmbralParameters().curve)
    assert new_cfrag.point_eph_e1 == cfrag.point_eph_e1
    assert new_cfrag.point_eph_v1 == cfrag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == cfrag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == cfrag.point_eph_ni


def test_capsule_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _, capsule = pre.encapsulate(pub_key)
    capsule_bytes = capsule.to_bytes()

    assert len(capsule_bytes) == 98

    new_capsule = umbral.Capsule.from_bytes(capsule_bytes,
                                            umbral.UmbralParameters().curve)
    assert new_capsule.point_eph_e == capsule.point_eph_e
    assert new_capsule.point_eph_v == capsule.point_eph_v
    assert new_capsule.bn_sig == capsule.bn_sig


def test_reconstructed_capsule_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _, capsule = pre.encapsulate(pub_key)
    kfrags, _ = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)

    rec_capsule = capsule.reconstruct()
    rec_capsule_bytes = rec_capsule.to_bytes()

    assert len(rec_capsule_bytes) == 99

    new_rec_capsule = umbral.ReconstructedCapsule.from_bytes(
                                rec_capsule_bytes,
                                umbral.UmbralParameters().curve)
    assert new_rec_capsule.point_eph_e_prime == rec_capsule.point_eph_e_prime
    assert new_rec_capsule.point_eph_v_prime == rec_capsule.point_eph_v_prime
    assert new_rec_capsule.point_eph_ni == rec_capsule.point_eph_ni


def test_challenge_response_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _, capsule = pre.encapsulate(pub_key)
    kfrags, _ = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)
    ch_resp = pre.challenge(kfrags[0], capsule, cfrag)

    ch_resp_bytes = ch_resp.to_bytes()
    assert len(ch_resp_bytes) == 228

    new_ch_resp = umbral.ChallengeResponse.from_bytes(
                            ch_resp_bytes, umbral.UmbralParameters().curve)
    assert new_ch_resp.point_eph_e2 == ch_resp.point_eph_e2
    assert new_ch_resp.point_eph_v2 == ch_resp.point_eph_v2
    assert new_ch_resp.point_kfrag_commitment == ch_resp.point_kfrag_commitment
    assert new_ch_resp.point_kfrag_pok == ch_resp.point_kfrag_pok
    assert new_ch_resp.bn_kfrag_sig1 == ch_resp.bn_kfrag_sig1
    assert new_ch_resp.bn_kfrag_sig2 == ch_resp.bn_kfrag_sig2
    assert new_ch_resp.bn_sig == ch_resp.bn_sig

# @pytest.mark.parametrize("N,threshold", parameters)
# def test_cheating_Ursula_replays_old_reencryption(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     pub_bob = pre.priv2pub(priv_bob)

#     sym_key, capsule_alice = pre.encapsulate(pub_alice)
#     _, other_capsule_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     cfrags = []
#     challenges = []
#     for kFrag in kfrags[:threshold]:
#         cFrag = pre.reencrypt(kFrag, capsule_alice)
#         challenge =  pre.challenge(kFrag, capsule_alice, cFrag)

#         #assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
#         cfrags.append(cFrag)
#         challenges.append(challenge)

#     # Let's put the re-encryption of a different Alice ciphertext
#     cfrags[0] = pre.reencrypt(kfrags[0], other_capsule_alice)

#     capsule_bob = pre.reconstruct_capsule(cfrags)

#     try:
#         # This line should always raise an AssertionError ("Generic Umbral Error")
#         sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule_bob, capsule_alice)
#         assert not sym_key_2 == sym_key
#     except AssertionError as e:
#         assert str(e) == "Generic Umbral Error"   
#         assert not pre.check_challenge(capsule_alice, cfrags[0], challenges[0], pub_alice)
#         # The response of cheating Ursula is in capsules[0], 
#         # so the rest of challenges chould be correct:
#         for (cFrag,ch) in zip(cfrags[1:], challenges[1:]):
#             assert pre.check_challenge(capsule_alice, cFrag, ch, pub_alice)


# @pytest.mark.parametrize("N,threshold", parameters)
# def test_cheating_ursula_sends_gargabe(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     pub_bob = pre.priv2pub(priv_bob)

#     sym_key, capsule_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     cfrags = []
#     challenges = []
#     for kFrag in kfrags[0:threshold]:
#         cFrag = pre.reencrypt(kFrag, capsule_alice)
#         challenge =  pre.challenge(kFrag, capsule_alice, cFrag)

#         #assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
#         cfrags.append(cFrag)
#         challenges.append(challenge)

#     # Let's put a random garbage in one of the cFrags 
#     cfrags[0].point_eph_e1 = Point.gen_rand(pre.curve)
#     cfrags[0].point_eph_v1 = Point.gen_rand(pre.curve)


#     capsule_bob = pre.reconstruct_capsule(cfrags)

#     try:
#         # This line should always raise an AssertionError ("Generic Umbral Error")
#         sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule_bob, capsule_alice)
#         assert not sym_key_2 == sym_key
#     except AssertionError as e:
#         assert str(e) == "Generic Umbral Error"
#         assert not pre.check_challenge(capsule_alice, cfrags[0], challenges[0], pub_alice)
#         # The response of cheating Ursula is in capsules[0], 
#         # so the rest of challenges chould be correct:
#         for (cFrag,ch) in zip(cfrags[1:], challenges[1:]):
#             assert pre.check_challenge(capsule_alice, cFrag, ch, pub_alice)


# @pytest.mark.parametrize("N,threshold", parameters)
# def test_alice_sends_fake_kFrag_to_ursula(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()

#     sym_key, capsule_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     # Alice tries to frame the first Ursula by sending her a random kFrag
#     fake_kfrag = kfrags[0]
#     fake_kfrag.point_key = BigNum.gen_rand(pre.curve)
#     assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)
