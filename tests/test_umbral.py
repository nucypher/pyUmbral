from umbral import umbral
import pytest
from umbral.bignum import BigNum
# import random
# from npre import umbral
# import npre.elliptic_curve as ec

# from npre.umbral import ReEncryptedKey

# (N,threshold)
parameters = [
    (1, 1),
    (3, 1),
    (3, 2),
    (5, 4),
    (10, 8),
    # (100, 85),
    # (100, 99),
    
    ]


def test_encrypt_decrypt():
    pre = umbral.PRE()

    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, ekey = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key should be used for block cipher

    sym_key_2 = pre.decapsulate_original(priv_key, ekey)
    assert sym_key_2 == sym_key


@pytest.mark.parametrize("N,threshold", parameters)
def test_m_of_n(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    cFrags = []
    for rk in kfrags[:threshold]:
        cFrag = pre.reencrypt(rk, ekey_alice)
        ch = pre.challenge(rk, ekey_alice, cFrag)
        assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
        cFrags.append(cFrag)

    ekey_bob = pre.reconstruct_capsule(cFrags)

    sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)
    assert sym_key_2 == sym_key

@pytest.mark.parametrize("N,threshold", parameters)
def test_m_of_n_cheating_Ursula_replays_old_reencryption(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    pub_bob = pre.priv2pub(priv_bob)

    sym_key, ekey_alice = pre.encapsulate(pub_alice)
    _, other_ekey_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    cFrags = []
    challenges = []
    for rk in kfrags[:threshold]:
        cFrag = pre.reencrypt(rk, ekey_alice)
        challenge =  pre.challenge(rk, ekey_alice, cFrag)
        
        #assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)
        cFrags.append(cFrag)
        challenges.append(challenge)

    # Let's put the re-encryption of a different Alice ciphertext
    cFrags[0] = pre.reencrypt(kfrags[0], other_ekey_alice)

    ekey_bob = pre.reconstruct_capsule(cFrags)
    
    try:
        # This line should always raise an AssertionError ("Generic Umbral Error")
        sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)
        assert not sym_key_2 == sym_key
    except AssertionError:#, match="Generic Umbral Error"):
        
        assert not pre.check_challenge(ekey_alice, cFrags[0], challenges[0], pub_alice)
        # The response of cheating Ursula is in ekeys[0], 
        # so the rest of challenges chould be correct:
        for (cFrag,ch) in zip(cFrags[1:], challenges[1:]):
            assert pre.check_challenge(ekey_alice, cFrag, ch, pub_alice)

    
@pytest.mark.parametrize("N,threshold", parameters)
def test_alice_sends_fake_kFrag_to_ursula(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    # Alice tries to frame the first Ursula by sending her a random kFrag
    fake_kfrag = kfrags[0]
    fake_kfrag.key = BigNum.gen_rand(pre.curve)
    assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)

# @pytest.mark.parametrize("N,threshold", parameters)
# def test_ursula_tries_to_send_gargabe(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     pub_bob = pre.priv2pub(priv_bob)

#     sym_key, ekey_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]

#     # Let's put garbage in one of the re-encrypted ciphertexts
#     ekey0, ch0 = ekeys[0]
#     ekey0 = ekey0._replace(
#         ekey=ec.random(pre.ecgroup, ec.G), 
#         vcomp=ec.random(pre.ecgroup, ec.G))
#     ekeys[0] = (ekey0, ch0)

#     ekey_bob = pre.combine(ekeys)
    
#     try:
#         # This line should always raise an AssertionError ("Generic Umbral Error")
#         sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)

#         # If we reach here, it means the validation doesn't work properly, 
#         # but still, the decapsulated key should be incorrect
#         assert not sym_key_2 == sym_key, "This just can't happen..."
#     except AssertionError as e:
#         assert str(e) == "Generic Umbral Error"
