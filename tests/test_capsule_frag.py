import pytest

from umbral import reencrypt, CapsuleFrag, PublicKey, Capsule, VerificationError
from umbral.curve_point import CurvePoint


def test_cfrag_serialization(verification_keys, capsule, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    metadata = b'This is an example of metadata for re-encryption request'
    for kfrag in kfrags:
        cfrag = reencrypt(capsule, kfrag, metadata=metadata)
        cfrag_bytes = bytes(cfrag)

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)

        verified_cfrag = new_cfrag.verify(capsule,
                                          verifying_pk=verifying_pk,
                                          delegating_pk=delegating_pk,
                                          receiving_pk=receiving_pk,
                                          metadata=metadata,
                                          )
        assert verified_cfrag == cfrag

        # No metadata
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=receiving_pk,
                             )

        # Wrong metadata
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=receiving_pk,
                             metadata=b'Not the same metadata',
                             )

        # Wrong delegating key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=receiving_pk,
                             receiving_pk=receiving_pk,
                             metadata=metadata,
                             )

        # Wrong receiving key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=delegating_pk,
                             metadata=metadata,
                             )

        # Wrong signing key
        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=receiving_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=receiving_pk,
                             metadata=metadata,
                             )


def test_cfrag_serialization_no_metadata(verification_keys, capsule, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    for kfrag in kfrags:

        # Create with no metadata
        cfrag = reencrypt(capsule, kfrag)
        cfrag_bytes = bytes(cfrag)
        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)

        verified_cfrag = new_cfrag.verify(capsule,
                                          verifying_pk=verifying_pk,
                                          delegating_pk=delegating_pk,
                                          receiving_pk=receiving_pk,
                                          )
        assert verified_cfrag == cfrag

        with pytest.raises(VerificationError):
            new_cfrag.verify(capsule,
                             verifying_pk=verifying_pk,
                             delegating_pk=delegating_pk,
                             receiving_pk=receiving_pk,
                             metadata=b'some metadata',
                             )


def test_cfrag_with_wrong_capsule(verification_keys, kfrags, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext
    verifying_pk, delegating_pk, receiving_pk = verification_keys

    capsule_alice1 = capsule
    capsule_alice2, _unused_key2 = Capsule.from_public_key(delegating_pk)

    metadata = b"some metadata"
    cfrag = reencrypt(capsule_alice2, kfrags[0], metadata=metadata)
    cfrag = CapsuleFrag.from_bytes(bytes(cfrag)) # de-verify

    with pytest.raises(VerificationError):
        cfrag.verify(capsule_alice1,
                     verifying_pk=verifying_pk,
                     delegating_pk=delegating_pk,
                     receiving_pk=receiving_pk,
                     metadata=metadata,
                     )


def test_cfrag_with_wrong_data(verification_keys, kfrags, capsule_and_ciphertext, message):

    capsule, ciphertext = capsule_and_ciphertext
    verifying_pk, delegating_pk, receiving_pk = verification_keys

    metadata = b"some metadata"
    cfrag = reencrypt(capsule, kfrags[0], metadata=metadata)

    # Let's put random garbage in one of the cfrags
    cfrag = CapsuleFrag.from_bytes(bytes(cfrag)) # de-verify
    cfrag.point_e1 = CurvePoint.random()
    cfrag.point_v1 = CurvePoint.random()

    with pytest.raises(VerificationError):
        cfrag.verify(capsule,
                     verifying_pk=verifying_pk,
                     delegating_pk=delegating_pk,
                     receiving_pk=receiving_pk,
                     metadata=metadata,
                     )


def test_cfrag_is_hashable(verification_keys, capsule, kfrags):

    verifying_pk, delegating_pk, receiving_pk = verification_keys

    cfrag0 = reencrypt(capsule, kfrags[0], metadata=b'abcdef')
    cfrag1 = reencrypt(capsule, kfrags[1], metadata=b'abcdef')

    assert hash(cfrag0) != hash(cfrag1)

    new_cfrag = CapsuleFrag.from_bytes(bytes(cfrag0))
    assert hash(new_cfrag) != hash(cfrag0)

    verified_cfrag = new_cfrag.verify(capsule,
                                      verifying_pk=verifying_pk,
                                      delegating_pk=delegating_pk,
                                      receiving_pk=receiving_pk,
                                      metadata=b'abcdef')

    assert hash(verified_cfrag) == hash(cfrag0)


def test_cfrag_str(capsule, kfrags):
    cfrag0 = reencrypt(capsule, kfrags[0], metadata=b'abcdef')
    s = str(cfrag0)
    assert 'VerifiedCapsuleFrag' in s

    s = str(CapsuleFrag.from_bytes(bytes(cfrag0)))
    assert "VerifiedCapsuleFrag" not in s
    assert "CapsuleFrag" in s
