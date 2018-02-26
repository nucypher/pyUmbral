from umbral import pre


def test_kfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)
    kfrag_bytes = kfrags[0].to_bytes()

    # A KFrag can be represented as the 194 total bytes of two Points (33 each) and four BigNums (32 each).
    assert len(kfrag_bytes) == 33 + 33 + (32 * 4) == 194

    new_frag = pre.KFrag.from_bytes(kfrag_bytes)
    assert new_frag.bn_id == kfrags[0].bn_id
    assert new_frag.bn_key == kfrags[0].bn_key
    assert new_frag.point_eph_ni == kfrags[0].point_eph_ni
    assert new_frag.point_commitment == kfrags[0].point_commitment
    assert new_frag.bn_sig1 == kfrags[0].bn_sig1
    assert new_frag.bn_sig2 == kfrags[0].bn_sig2


def test_cfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    k_frags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    c_frag = pre.reencrypt(k_frags[0], capsule)
    c_frag_bytes = c_frag.to_bytes()

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    assert len(c_frag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(c_frag_bytes)
    assert new_cfrag.point_eph_e1 == c_frag.point_eph_e1
    assert new_cfrag.point_eph_v1 == c_frag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == c_frag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == c_frag.point_eph_ni
