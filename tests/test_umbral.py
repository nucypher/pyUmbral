import pytest

from umbral import umbral, keys
from umbral.bignum import BigNum
from umbral.point import Point
from umbral.umbral import Capsule

parameters = [
    # (N,threshold)
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

    sym_key, capsule = pre._encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key is perhaps used for block cipher here in a real-world scenario.

    sym_key_2 = pre._decapsulate_original(priv_key, capsule)
    assert sym_key_2 == sym_key


@pytest.mark.parametrize("N,threshold", parameters)
def test_simple_api(N, threshold):
    params = umbral.UmbralParameters()
    pre = umbral.PRE(params)

    priv_key_alice = keys.UmbralPrivateKey.gen_key(params)
    pub_key_alice = priv_key_alice.get_pub_key(params)

    priv_key_bob = keys.UmbralPrivateKey.gen_key(params)
    pub_key_bob = priv_key_bob.get_pub_key(params)

    plain_data = b'attack at dawn'
    enc_data, capsule = pre.encrypt(pub_key_alice, plain_data)

    dec_data = pre.decrypt(priv_key_alice, capsule, enc_data)
    assert dec_data == plain_data

    rekeys, _unused_vkeys = pre.split_rekey(priv_key_alice, pub_key_bob, threshold, N)
    for rekey in rekeys:
        cFrag = pre.reencrypt(rekey, capsule)
        capsule.attach_cfrag(cFrag)

    reenc_dec_data = capsule.decrypt(
        priv_key_bob, pub_key_alice, enc_data, pre
    )
    assert reenc_dec_data == plain_data


def test_bad_capsule_fails_reencryption():
    pre = umbral.PRE()

    priv_key_alice = keys.UmbralPrivateKey.gen_key(pre.params)
    pub_key_alice = priv_key_alice.get_pub_key(pre.params)

    k_frags, _unused_vkeys = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    bollocks_capsule = Capsule(point_eph_e=Point.gen_rand(curve=pre.params.curve),
                               point_eph_v=Point.gen_rand(curve=pre.params.curve),
                               bn_sig=BigNum.gen_rand(curve=pre.params.curve))

    with pytest.raises(Capsule.NotValid):
        pre.reencrypt(k_frags[0], bollocks_capsule)


def test_two_unequal_capsules():
    pre = umbral.PRE()
    one_capsule = Capsule(point_eph_e=Point.gen_rand(curve=pre.params.curve),
                               point_eph_v=Point.gen_rand(curve=pre.params.curve),
                               bn_sig=BigNum.gen_rand(curve=pre.params.curve))

    another_capsule = Capsule(point_eph_e=Point.gen_rand(curve=pre.params.curve),
                          point_eph_v=Point.gen_rand(curve=pre.params.curve),
                          bn_sig=BigNum.gen_rand(curve=pre.params.curve))

    assert one_capsule != another_capsule

    reconstructed_capsule = Capsule(e_prime=Point.gen_rand(curve=pre.params.curve),
                                    v_prime=Point.gen_rand(curve=pre.params.curve),
                                    noninteractive_point=Point.gen_rand(curve=pre.params.curve))

    assert reconstructed_capsule != one_capsule


@pytest.mark.parametrize("N,threshold", parameters)
def test_m_of_n(N, threshold):
    pre = umbral.PRE(umbral.UmbralParameters())
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, capsule = pre._encapsulate(pub_alice)
    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_alice, pub_bob, pre.params)
        assert kfrag.is_consistent(vkeys, pre.params)

    for kfrag in kfrags[:threshold]:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)
        ch = pre.challenge(kfrag, capsule, cfrag)
        assert pre.check_challenge(capsule, cfrag, ch, pub_alice, pub_bob)

    # assert capsule.is_openable_by_bob()  # TODO: Is it possible to check here if >= m cFrags have been attached?
    # capsule.open(pub_bob, priv_bob, pub_alice)

    capsule._reconstruct()
    sym_key_from_capsule = pre.decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule)
    assert sym_key == sym_key_from_capsule


def test_kfrag_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    kfrags, _unused_vkeys = pre.split_rekey(priv_key, pub_key, 1, 2)
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

    _unused_key, capsule = pre._encapsulate(pub_key)
    kfrags, _unused_vkeys = pre.split_rekey(priv_key, pub_key, 1, 2)

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

    _symmetric_key, capsule = pre._encapsulate(pub_key)
    capsule_bytes = capsule.to_bytes()

    # A Capsule can be represented as the 98 total bytes of two Points (33 each) and a BigNum (32).
    assert len(capsule_bytes) == 33 + 33 + 32 == 98

    new_capsule = umbral.Capsule.from_bytes(capsule_bytes,
                                            umbral.UmbralParameters().curve)

    # Three ways to think about equality.
    # First, the public approach for the Capsule.  Simply:
    new_capsule == capsule

    # Second, we show that the original components (which is all we have here since we haven't reconstructed) are the same:
    assert new_capsule.original_components() == capsule.original_components()

    # Third, we can directly compare the private original component attributes (though this is not a supported approach):
    assert new_capsule._point_eph_e == capsule._point_eph_e
    assert new_capsule._point_eph_v == capsule._point_eph_v
    assert new_capsule._bn_sig == capsule._bn_sig


def test_reconstructed_capsule_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _unused_key, capsule = pre._encapsulate(pub_key)
    kfrags, _unused_vkeys = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)

    capsule._reconstruct()
    rec_capsule_bytes = capsule.to_bytes(reconstructed_components=True)

    # A reconstructed Capsule is:
    # three points, representable as 33 bytes each (the original), and
    # two points and a bignum (32 bytes) (the activated components), for 197 total.
    assert len(rec_capsule_bytes) == (33 * 3) + (33 + 33 + 32)

    new_rec_capsule = umbral.Capsule.from_bytes(
        rec_capsule_bytes,
        umbral.UmbralParameters().curve, is_reconstructed=True)

    # Again, the same three perspectives on equality. 
    new_rec_capsule == capsule

    assert new_rec_capsule.reconstructed_components() == capsule.reconstructed_components()

    assert new_rec_capsule._point_eph_e_prime == capsule._point_eph_e_prime
    assert new_rec_capsule._point_eph_v_prime == capsule._point_eph_v_prime
    assert new_rec_capsule._point_noninteractive == capsule._point_noninteractive


def test_challenge_response_serialization():
    pre = umbral.PRE(umbral.UmbralParameters())

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _unused_key, capsule = pre._encapsulate(pub_key)
    kfrags, _unused_vkeys = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)
    ch_resp = pre.challenge(kfrags[0], capsule, cfrag)

    ch_resp_bytes = ch_resp.to_bytes()

    # A ChallengeResponse can be represented as the 228 total bytes of four Points (33 each) and three BigNums (32 each).
    assert len(ch_resp_bytes) == (33 * 4) + (32 * 3) == 228

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

#     sym_key, capsule_alice = pre._encapsulate(pub_alice)
#     _, other_capsule_alice = pre._encapsulate(pub_alice)

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
#         sym_key_2 = pre._decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule_bob, capsule_alice)
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

#     sym_key, capsule_alice = pre._encapsulate(pub_alice)

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
#         sym_key_2 = pre._decapsulate_reencrypted(pub_bob, priv_bob, pub_alice, capsule_bob, capsule_alice)
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

#     sym_key, capsule_alice = pre._encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     # Alice tries to frame the first Ursula by sending her a random kFrag
#     fake_kfrag = kfrags[0]
#     fake_kfrag.point_key = BigNum.gen_rand(pre.curve)
#     assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)
