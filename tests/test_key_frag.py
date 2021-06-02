import pytest

from umbral import KeyFrag, PublicKey, Signer, VerificationError
from umbral.key_frag import KeyFragID, KeyFragBase, VerifiedKeyFrag
from umbral.curve_scalar import CurveScalar


def test_kfrag_serialization(verification_keys, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    for kfrag in kfrags:
        kfrag_bytes = bytes(kfrag)
        new_kfrag = KeyFrag.from_bytes(kfrag_bytes)

        new_kfrag = new_kfrag.verify(verifying_pk=verifying_pk,
                                     delegating_pk=delegating_pk,
                                     receiving_pk=receiving_pk)

        assert new_kfrag == kfrag


def test_kfrag_verification(verification_keys, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    # Wrong signature
    kfrag = kfrags[0]
    kfrag.kfrag.id = KeyFragID.random()
    kfrag_bytes = bytes(kfrag)
    new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
    with pytest.raises(VerificationError):
        new_kfrag.verify(verifying_pk=verifying_pk,
                         delegating_pk=delegating_pk,
                         receiving_pk=receiving_pk)

    # Wrong key
    kfrag = kfrags[1]
    kfrag.kfrag.key = CurveScalar.random_nonzero()
    kfrag_bytes = bytes(kfrag)
    new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
    with pytest.raises(VerificationError):
        new_kfrag.verify(verifying_pk=verifying_pk,
                         delegating_pk=delegating_pk,
                         receiving_pk=receiving_pk)


@pytest.mark.parametrize('sign_delegating_key',
                         [False, True],
                         ids=['sign_delegating_key', 'dont_sign_delegating_key'])
@pytest.mark.parametrize('sign_receiving_key',
                         [False, True],
                         ids=['sign_receiving_key', 'dont_sign_receiving_key'])
def test_kfrag_signing(alices_keys, bobs_keys, sign_delegating_key, sign_receiving_key):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    verifying_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    base = KeyFragBase(delegating_sk=delegating_sk,
                       receiving_pk=receiving_pk,
                       signer=Signer(signing_sk),
                       threshold=6)

    kfrag = KeyFrag.from_base(base=base,
                              sign_delegating_key=sign_delegating_key,
                              sign_receiving_key=sign_receiving_key)

    # serialize/deserialize to make sure sign_* fields are serialized correctly
    kfrag = KeyFrag.from_bytes(bytes(kfrag))

    for pass_delegating_key, pass_receiving_key in zip([False, True], [False, True]):

        delegating_key_ok = (not sign_delegating_key) or pass_delegating_key
        receiving_key_ok = (not sign_receiving_key) or pass_receiving_key
        should_verify = delegating_key_ok and receiving_key_ok

        verification_passed = True
        try:
            kfrag.verify(verifying_pk=verifying_pk,
                         delegating_pk=delegating_pk if pass_delegating_key else None,
                         receiving_pk=receiving_pk if pass_receiving_key else None)
        except VerificationError:
            verification_passed = False

        assert verification_passed == should_verify


def test_wrong_threshold(alices_keys, bobs_keys):
    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    with pytest.raises(ValueError):
        KeyFragBase(delegating_sk=delegating_sk,
                    receiving_pk=receiving_pk,
                    signer=Signer(signing_sk),
                    threshold=0)


def test_kfrag_is_hashable(verification_keys, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    assert hash(kfrags[0]) != hash(kfrags[1])

    new_kfrag = KeyFrag.from_bytes(bytes(kfrags[0]))

    # Not verified yet
    assert hash(new_kfrag) != hash(kfrags[0])

    verified_kfrag = new_kfrag.verify(verifying_pk=verifying_pk,
                                      delegating_pk=delegating_pk,
                                      receiving_pk=receiving_pk)

    assert hash(verified_kfrag) == hash(kfrags[0])


def test_kfrag_str(kfrags):
    s = str(kfrags[0])
    assert "VerifiedKeyFrag" in s

    s = str(KeyFrag.from_bytes(bytes(kfrags[0])))
    assert "VerifiedKeyFrag" not in s
    assert "KeyFrag" in s


def test_from_verified_bytes(kfrags):
    kfrag_bytes = bytes(kfrags[0])
    verified_kfrag = VerifiedKeyFrag.from_verified_bytes(kfrag_bytes)
    assert verified_kfrag == kfrags[0]
