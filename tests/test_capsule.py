import pytest

from umbral import (
    Capsule,
    SecretKey,
    PublicKey,
    GenericError,
    encrypt,
    decrypt_original,
    reencrypt,
    decrypt_reencrypted,
    generate_kfrags
    )
from umbral.curve_point import CurvePoint


def test_capsule_serialization(alices_keys):

    delegating_sk, _signing_sk = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    capsule, _key = Capsule.from_public_key(delegating_pk)
    new_capsule = Capsule.from_bytes(bytes(capsule))

    assert capsule == new_capsule

    # Deserializing a bad capsule triggers verification error
    capsule.point_e = CurvePoint.random()
    capsule_bytes = bytes(capsule)

    with pytest.raises(GenericError):
        Capsule.from_bytes(capsule_bytes)


def test_capsule_is_hashable(alices_keys):

    delegating_sk, _signing_sk = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    capsule1, key1 = Capsule.from_public_key(delegating_pk)
    capsule2, key2 = Capsule.from_public_key(delegating_pk)

    assert capsule1 != capsule2
    assert key1 != key2
    assert hash(capsule1) != hash(capsule2)

    new_capsule = Capsule.from_bytes(bytes(capsule1))
    assert hash(new_capsule) == hash(capsule1)


def test_open_original(alices_keys):

    delegating_sk, _signing_sk = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    capsule, key = Capsule.from_public_key(delegating_pk)
    key_back = capsule.open_original(delegating_sk)
    assert key == key_back


def test_open_reencrypted(alices_keys, bobs_keys):

    threshold = 6
    num_kfrags = 10

    delegating_sk, signing_sk = alices_keys
    receiving_sk, receiving_pk = bobs_keys

    signing_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    capsule, key = Capsule.from_public_key(delegating_pk)
    kfrags = generate_kfrags(delegating_sk=delegating_sk,
                             signing_sk=signing_sk,
                             receiving_pk=receiving_pk,
                             threshold=threshold,
                             num_kfrags=num_kfrags)

    cfrags = [reencrypt(capsule, kfrag) for kfrag in kfrags]
    key_back = capsule.open_reencrypted(receiving_sk, delegating_pk, cfrags[:threshold])
    assert key_back == key

    # No cfrags at all
    with pytest.raises(ValueError, match="Empty CapsuleFrag sequence"):
        capsule.open_reencrypted(receiving_sk, delegating_pk, [])

    # Not enough cfrags
    with pytest.raises(GenericError, match="Internal validation failed"):
        capsule.open_reencrypted(receiving_sk, delegating_pk, cfrags[:threshold-1])

    # Repeating cfrags
    with pytest.raises(ValueError, match="Some of the CapsuleFrags are repeated"):
        capsule.open_reencrypted(receiving_sk, delegating_pk, [cfrags[0]] + cfrags[:threshold-1])

    # Mismatched cfrags
    kfrags2 = generate_kfrags(delegating_sk=delegating_sk,
                              signing_sk=signing_sk,
                              receiving_pk=receiving_pk,
                              threshold=threshold,
                              num_kfrags=num_kfrags)
    cfrags2 = [reencrypt(capsule, kfrag) for kfrag in kfrags2]
    with pytest.raises(ValueError, match="CapsuleFrags are not pairwise consistent"):
        capsule.open_reencrypted(receiving_sk, delegating_pk, [cfrags2[0]] + cfrags[:threshold-1])


def test_capsule_str(capsule):
    s = str(capsule)
    assert 'Capsule' in s
