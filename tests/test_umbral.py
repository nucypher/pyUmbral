from umbral import umbral
import pytest
# import random
# from npre import umbral
# import npre.elliptic_curve as ec

# from npre.umbral import ReEncryptedKey

# (N,threshold)
parameters = [
    #(10, 8),
    (3, 2),
    #(5, 4),
    # (100, 85),
    # (100, 99),
    #(1, 1),
    #(3, 1)
    ]

# def test_basic():
#     pre = umbral.PRE()
#     print(pre.g)
#     print(pre.order)

#     priv_a = pre.gen_priv()
#     priv_b = pre.gen_priv()

#     pub_a = priv_a.public_key()
#     pub_b = priv_b.public_key()

#     # rks = pre.split_rekey(priv_a, priv_b, 2, 3)

#     # plain1, enc_a = pre.encapsulate(pub_a)
#     # shares = [pre.reencrypt(rk, enc_a) for rk in rks]
#     # sec = pre.combine(shares)




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

    

    # for kfrag in kfrags:
    #     assert pre.check_kFrag_consistency(kfrag, vkeys)

    # ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]

    # for (ekey,ch) in ekeys:
    #     assert pre.check_challenge(ekey_alice, ekey, ch, pub_alice)

    # ekey_bob = pre.combine(ekeys)

    # sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)
    # assert sym_key_2 == sym_key

# @pytest.mark.parametrize("N,threshold", parameters)
# def test_m_of_n_when_an_Ursula_tries_to_cheat(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     pub_bob = pre.priv2pub(priv_bob)

#     sym_key, ekey_alice = pre.encapsulate(pub_alice)
#     _, other_ekey_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, pub_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]


#     # Let's put the re-encryption of a different Alice ciphertext
#     ekeys[0] = pre.reencrypt(kfrags[0], other_ekey_alice)

#     ekey_bob = pre.combine(ekeys)
    
#     try:
#         # This line should always raise an AssertionError ("Generic Umbral Error")
#         sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)
#     except AssertionError:#, match="Generic Umbral Error"):
        
#         # The response of cheating Ursula is in ekeys[0], 
#         # so the rest of challenges chould be correct:
#         for (ekey,ch) in ekeys[1:]:
#             assert pre.check_challenge(ekey_alice, ekey, ch, pub_alice)

#         ekey, ch = ekeys[0]
#         assert not pre.check_challenge(ekey_alice, ekey, ch, pub_alice)


# @pytest.mark.parametrize("N,threshold", parameters)
# def test_alice_sends_fake_kFrag_to_ursula(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()

#     sym_key, ekey_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     # Alice tries to frame the first Ursula by sending her a random kFrag
#     fake_kfrag = kfrags[0]._replace(key=ec.random(pre.ecgroup, ec.ZR))
#     assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)

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


# @pytest.mark.parametrize("N,threshold", parameters)
# def test_ursula_tries_to_send_previous_reencryption(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     pub_bob = pre.priv2pub(priv_bob)

#     sym_key, ekey_alice = pre.encapsulate(pub_alice)
#     _, other_ekey_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)


#     ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]

#     # Let's put another re-encryption of an Alice ciphertext
#     ekeys[0] = pre.reencrypt(kfrags[0], other_ekey_alice)

#     ekey_bob = pre.combine(ekeys)

#     try:
#         # This line should always raise an AssertionError ("Generic Umbral Error")
#         sym_key_2 = pre.decapsulate_reencrypted(pub_bob, priv_bob, ekey_bob, pub_alice, ekey_alice)

#         # If we reach here, it means the validation doesn't work properly, 
#         # but still, the decapsulated key should be incorrect
#         assert not sym_key_2 == sym_key, "This just can't happen..."
#     except AssertionError as e:
#         assert str(e) == "Generic Umbral Error"
