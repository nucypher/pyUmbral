from umbral import pre


def test_capsule_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _symmetric_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    capsule_bytes = capsule.to_bytes()
    capsule_bytes_casted = bytes(capsule)
    assert capsule_bytes == capsule_bytes_casted

    # A Capsule can be represented as the 98 total bytes of two Points (33 each) and a BigNum (32).
    assert len(capsule_bytes) == 33 + 33 + 32 == 98

    new_capsule = pre.Capsule.from_bytes(capsule_bytes)

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
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    _unused_key, capsule = pre._encapsulate(pub_key)
    kfrags, _unused_vkeys = pre.split_rekey(priv_key, pub_key, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.attach_cfrag(cfrag)

    capsule._reconstruct_shamirs_secret()
    rec_capsule_bytes = capsule.to_bytes()

    # An activated Capsule is:
    # three points, representable as 33 bytes each (the original), and
    # two points and a bignum (32 bytes) (the activated components), for 197 total.
    assert len(rec_capsule_bytes) == (33 * 3) + (33 + 33 + 32)

    new_rec_capsule = pre.Capsule.from_bytes(rec_capsule_bytes)

    # Again, the same three perspectives on equality.
    assert new_rec_capsule == capsule

    assert new_rec_capsule.activated_components() == capsule.activated_components()

    assert new_rec_capsule._point_eph_e_prime == capsule._point_eph_e_prime
    assert new_rec_capsule._point_eph_v_prime == capsule._point_eph_v_prime
    assert new_rec_capsule._point_noninteractive == capsule._point_noninteractive