from umbral import umbral
import pytest
from umbral.bignum import BigNum
from umbral.point import Point

# (N,threshold)
parameters = [
    (1, 1),
    (6,1),
    (6,4),
    (6,6),
    (50, 30)
    ]


def test_encrypt_decrypt():
    pre = umbral.PRE()

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, capsule = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key should be used for block cipher

    sym_key_2 = pre.decapsulate_original(priv_key, capsule)
    assert sym_key_2 == sym_key


@pytest.mark.parametrize("N,threshold", parameters)
def test_m_of_n(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, capsule_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_signature(kfrag, pub_alice)
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    cFrags = []
    for kFrag in kfrags[:threshold]:
        cFrag = pre.reencrypt(kFrag, capsule_alice)
        ch = pre.challenge(kFrag, capsule_alice, cFrag)
        assert pre.check_challenge(capsule_alice, cFrag, ch, pub_alice)
        cFrags.append(cFrag)

    capsule_bob = pre.reconstruct_capsule(cFrags)

    sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, capsule_bob, pub_alice, capsule_alice)
    assert sym_key_2 == sym_key

@pytest.mark.parametrize("N,threshold", parameters)
def test_cheating_Ursula_replays_old_reencryption(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, capsule_alice = pre.encapsulate(pub_alice)
    _, other_capsule_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    cFrags = []
    challenges = []
    for kFrag in kfrags[:threshold]:
        cFrag = pre.reencrypt(kFrag, capsule_alice)
        challenge =  pre.challenge(kFrag, capsule_alice, cFrag)
        
        #assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
        cFrags.append(cFrag)
        challenges.append(challenge)

    # Let's put the re-encryption of a different Alice ciphertext
    cFrags[0] = pre.reencrypt(kfrags[0], other_capsule_alice)

    capsule_bob = pre.reconstruct_capsule(cFrags)
    
    try:
        # This line should always raise an AssertionError ("Generic Umbral Error")
        sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, capsule_bob, pub_alice, capsule_alice)
        assert not sym_key_2 == sym_key
    except AssertionError as e:
        assert str(e) == "Generic Umbral Error"   
        assert not pre.check_challenge(capsule_alice, cFrags[0], challenges[0], pub_alice)
        # The response of cheating Ursula is in capsules[0], 
        # so the rest of challenges chould be correct:
        for (cFrag,ch) in zip(cFrags[1:], challenges[1:]):
            assert pre.check_challenge(capsule_alice, cFrag, ch, pub_alice)


@pytest.mark.parametrize("N,threshold", parameters)
def test_cheating_ursula_sends_gargabe(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, capsule_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    cFrags = []
    challenges = []
    for kFrag in kfrags[0:threshold]:
        cFrag = pre.reencrypt(kFrag, capsule_alice)
        challenge =  pre.challenge(kFrag, capsule_alice, cFrag)
        
        #assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
        cFrags.append(cFrag)
        challenges.append(challenge)

    # Let's put a random garbage in one of the cFrags 
    cFrags[0].e1 = Point.gen_rand(pre.curve)
    cFrags[0].v1 = Point.gen_rand(pre.curve)


    capsule_bob = pre.reconstruct_capsule(cFrags)
    
    try:
        # This line should always raise an AssertionError ("Generic Umbral Error")
        sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, capsule_bob, pub_alice, capsule_alice)
        assert not sym_key_2 == sym_key
    except AssertionError as e:
        assert str(e) == "Generic Umbral Error"
        assert not pre.check_challenge(capsule_alice, cFrags[0], challenges[0], pub_alice)
        # The response of cheating Ursula is in capsules[0], 
        # so the rest of challenges chould be correct:
        for (cFrag,ch) in zip(cFrags[1:], challenges[1:]):
            assert pre.check_challenge(capsule_alice, cFrag, ch, pub_alice)

@pytest.mark.parametrize("N,threshold", parameters)
def test_alice_sends_fake_kFrag_to_ursula(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()

    sym_key, capsule_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    # Alice tries to frame the first Ursula by sending her a random kFrag
    fake_kfrag = kfrags[0]
    fake_kfrag.point_key = BigNum.gen_rand(pre.curve)
    assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)
