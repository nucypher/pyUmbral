from umbral import reencrypt, CapsuleFrag, PublicKey, Capsule
from umbral.curve_point import CurvePoint


def test_cfrag_serialization(alices_keys, bobs_keys, capsule, kfrags):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    verifying_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    metadata = b'This is an example of metadata for re-encryption request'
    for kfrag in kfrags:
        cfrag = reencrypt(capsule, kfrag, metadata=metadata)
        cfrag_bytes = bytes(cfrag)

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)
        assert new_cfrag == cfrag

        assert new_cfrag.verify(capsule,
                                verifying_pk=verifying_pk,
                                delegating_pk=delegating_pk,
                                receiving_pk=receiving_pk,
                                metadata=metadata,
                                )

        # No metadata
        assert not new_cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    )

        # Wrong metadata
        assert not new_cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    metadata=b'Not the same metadata',
                                    )

        # Wrong delegating key
        assert not new_cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=receiving_pk,
                                    receiving_pk=receiving_pk,
                                    metadata=metadata,
                                    )

        # Wrong receiving key
        assert not new_cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=delegating_pk,
                                    metadata=metadata,
                                    )

        # Wrong signing key
        assert not new_cfrag.verify(capsule,
                                    verifying_pk=receiving_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    metadata=metadata,
                                    )


def test_cfrag_serialization_no_metadata(alices_keys, bobs_keys, capsule, kfrags):

    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    verifying_pk = PublicKey.from_secret_key(signing_sk)
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    for kfrag in kfrags:

        # Create with no metadata
        cfrag = reencrypt(capsule, kfrag)
        cfrag_bytes = bytes(cfrag)
        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)

        assert new_cfrag.verify(capsule,
                                verifying_pk=verifying_pk,
                                delegating_pk=delegating_pk,
                                receiving_pk=receiving_pk,
                                )

        assert not new_cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    metadata=b'some metadata',
                                    )


def test_cfrag_with_wrong_capsule(alices_keys, bobs_keys,
                                  kfrags, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext

    delegating_sk, signing_sk = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    _receiving_sk, receiving_pk = bobs_keys

    capsule_alice1 = capsule
    capsule_alice2, _unused_key2 = Capsule.from_public_key(delegating_pk)

    metadata = b"some metadata"
    cfrag = reencrypt(capsule_alice2, kfrags[0], metadata=metadata)

    assert not cfrag.verify(capsule_alice1,
                            verifying_pk=PublicKey.from_secret_key(signing_sk),
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk,
                            metadata=metadata,
                            )


def test_cfrag_with_wrong_data(kfrags, alices_keys, bobs_keys, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext

    delegating_sk, signing_sk = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    _receiving_sk, receiving_pk = bobs_keys

    metadata = b"some metadata"
    cfrag = reencrypt(capsule, kfrags[0], metadata=metadata)

    # Let's put random garbage in one of the cfrags
    cfrag.point_e1 = CurvePoint.random()
    cfrag.point_v1 = CurvePoint.random()

    assert not cfrag.verify(capsule,
                            verifying_pk=PublicKey.from_secret_key(signing_sk),
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk,
                            metadata=metadata,
                            )


def test_cfrag_is_hashable(capsule, kfrags):

    cfrag0 = reencrypt(capsule, kfrags[0], metadata=b'abcdef')
    cfrag1 = reencrypt(capsule, kfrags[1], metadata=b'abcdef')

    assert hash(cfrag0) != hash(cfrag1)

    new_cfrag = CapsuleFrag.from_bytes(bytes(cfrag0))
    assert hash(new_cfrag) == hash(cfrag0)


def test_cfrag_str(capsule, kfrags):
    cfrag0 = reencrypt(capsule, kfrags[0], metadata=b'abcdef')
    s = str(cfrag0)
    assert 'CapsuleFrag' in s
