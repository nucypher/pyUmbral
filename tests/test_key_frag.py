import pytest

from umbral import KeyFrag, PublicKey, generate_kfrags
from umbral.key_frag import KeyFragID
from umbral.curve_scalar import CurveScalar


def test_kfrag_serialization(alices_keys, bobs_keys, kfrags):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    signing_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    for kfrag in kfrags:
        kfrag_bytes = bytes(kfrag)
        new_kfrag = KeyFrag.from_bytes(kfrag_bytes)

        assert new_kfrag.verify(signing_pk=signing_pk,
                                delegating_pk=delegating_pk,
                                receiving_pk=receiving_pk)

        assert new_kfrag == kfrag


def test_kfrag_verification(alices_keys, bobs_keys, kfrags):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    signing_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    # Wrong signature
    kfrag = kfrags[0]
    kfrag.id = KeyFragID.random()
    kfrag_bytes = bytes(kfrag)
    new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
    assert not new_kfrag.verify(signing_pk=signing_pk,
                                delegating_pk=delegating_pk,
                                receiving_pk=receiving_pk)

    # Wrong key
    kfrag = kfrags[1]
    kfrag.key = CurveScalar.random_nonzero()
    kfrag_bytes = bytes(kfrag)
    new_kfrag = KeyFrag.from_bytes(kfrag_bytes)
    assert not new_kfrag.verify(signing_pk=signing_pk,
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

    signing_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    kfrags = generate_kfrags(delegating_sk=delegating_sk,
                             signing_sk=signing_sk,
                             receiving_pk=receiving_pk,
                             threshold=6,
                             num_kfrags=10,
                             sign_delegating_key=sign_delegating_key,
                             sign_receiving_key=sign_receiving_key)

    kfrag = kfrags[0]

    # serialize/deserialize to make sure sign_* fields are serialized correctly
    kfrag = KeyFrag.from_bytes(bytes(kfrag))

    for pass_delegating_key, pass_receiving_key in zip([False, True], [False, True]):

        delegating_key_ok = (not sign_delegating_key) or pass_delegating_key
        receiving_key_ok = (not sign_receiving_key) or pass_receiving_key
        should_verify = delegating_key_ok and receiving_key_ok

        result = kfrag.verify(signing_pk=signing_pk,
                              delegating_pk=delegating_pk if pass_delegating_key else None,
                              receiving_pk=receiving_pk if pass_receiving_key else None)

        assert result == should_verify


def test_kfrag_is_hashable(kfrags):

    assert hash(kfrags[0]) != hash(kfrags[1])

    new_kfrag = KeyFrag.from_bytes(bytes(kfrags[0]))
    assert hash(new_kfrag) == hash(kfrags[0])


def test_kfrag_str(kfrags):
    s = str(kfrags[0])
    assert "KeyFrag" in s


WRONG_PARAMETERS = (
    # (num_kfrags, threshold)
    (-1, -1),   (-1, 0),    (-1, 5),
    (0, -1),    (0, 0),     (0, 5),
    (1, -1),    (1, 0),     (1, 5),
    (5, -1),    (5, 0),     (5, 10)
)

@pytest.mark.parametrize("num_kfrags, threshold", WRONG_PARAMETERS)
def test_wrong_threshold_and_num_kfrags(num_kfrags, threshold, alices_keys, bobs_keys):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    with pytest.raises(ValueError):
        generate_kfrags(delegating_sk=delegating_sk,
                        signing_sk=signing_sk,
                        receiving_pk=receiving_pk,
                        threshold=threshold,
                        num_kfrags=num_kfrags)
