import pytest

from umbral import pre, keys
from umbral.point import Point
from umbral.fragments import CorrectnessProof
from .conftest import parameters

import time


def test_correctness_proof_serialization():
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, 1, 2)

    # Example of potential metadata to describe the re-encryption request
    metadata = b"This is an example of metadata for re-encryption request"

    cfrag = pre.reencrypt(kfrags[0], capsule, metadata=metadata)

    capsule.attach_cfrag(cfrag)

    proof = cfrag.proof
    proof_bytes = proof.to_bytes()

    # A CorrectnessProof can be represented as
    # the 228 total bytes of four Points (33 each) and three BigNums (32 each).
    # TODO: Figure out final size for CorrectnessProofs
    # assert len(proof_bytes) == (33 * 4) + (32 * 3) == 228

    new_proof = CorrectnessProof.from_bytes(proof_bytes)
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof._bn_kfrag_sig1 == proof._bn_kfrag_sig1
    assert new_proof._bn_kfrag_sig2 == proof._bn_kfrag_sig2
    assert new_proof._bn_sig == proof._bn_sig
    assert new_proof.metadata == proof.metadata


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_replays_old_reencryption(N, M):
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key_alice1, capsule_alice1 = pre._encapsulate(pub_key_alice.point_key)
    sym_key_alice2, capsule_alice2 = pre._encapsulate(pub_key_alice.point_key)

    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    cfrags, metadata = [], []
    for i, kfrag in enumerate(kfrags):

        # Example of potential metadata to describe the re-encryption request
        metadata_i = "This is an example of metadata for re-encryption request #{}"
        metadata_i = metadata_i.format(i).encode()

        if i == 0:
            # Let's put the re-encryption of a different Alice ciphertext
            cfrag = pre.reencrypt(kfrag, capsule_alice2, metadata=metadata_i)
        else:
            cfrag = pre.reencrypt(kfrag, capsule_alice1, metadata=metadata_i)

        capsule_alice1.attach_cfrag(cfrag)

        cfrags.append(cfrag)

    # Let's activate the capsule
    capsule_alice1._reconstruct_shamirs_secret(pub_key_alice, priv_key_bob)    

    with pytest.raises(pre.GenericUmbralError):
        sym_key = pre._decapsulate_reencrypted(pub_key_bob.point_key,
                                               priv_key_bob.bn_key,
                                               pub_key_alice.point_key,
                                               capsule_alice1
                                              )

    assert not pre._verify_correctness(capsule_alice1,
                                       cfrags[0],
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                      )

    # The response of cheating Ursula is in cfrags[0],
    # so the rest of CFrags should be correct:
    for cfrag_i, metadata_i in zip(cfrags[1:], metadata[1:]):
        assert pre._verify_correctness(capsule_alice1,
                                       cfrag_i,
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                      )

    # Alternatively, we can try to open the capsule directly.
    # We should get an exception with an attached list of incorrect cfrags
    with pytest.raises(pre.UmbralCorrectnessError) as exception_info:
        _ = pre._open_capsule(capsule_alice1, priv_key_bob, pub_key_alice)
    correctness_error = exception_info.value
    assert cfrags[0] in correctness_error.offending_cfrags
    assert len(correctness_error.offending_cfrags) == 1


@pytest.mark.parametrize("N, M", parameters)
def test_cheating_ursula_sends_garbage(N, M):
    priv_key_alice = keys.UmbralPrivateKey.gen_key()
    pub_key_alice = priv_key_alice.get_pubkey()

    # Bob
    priv_key_bob = keys.UmbralPrivateKey.gen_key()
    pub_key_bob = priv_key_bob.get_pubkey()

    sym_key, capsule_alice = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    cfrags, metadata = [], []
    for i, kfrag in enumerate(kfrags[:M]):

        # Example of potential metadata to describe the re-encryption request
        metadata_i = "This is an example of metadata for re-encryption request #{}"
        metadata_i = metadata_i.format(i).encode()

        cfrag = pre.reencrypt(kfrag, capsule_alice, metadata=metadata_i)

        capsule_alice.attach_cfrag(cfrag)
        cfrags.append(cfrag)

    # Let's put random garbage in one of the cfrags
    cfrags[0]._point_e1 = Point.gen_rand()
    cfrags[0]._point_v1 = Point.gen_rand()

    capsule_alice._reconstruct_shamirs_secret(pub_key_alice, priv_key_bob)    # activate capsule

    with pytest.raises(pre.GenericUmbralError):
        _unused_key = pre._decapsulate_reencrypted(pub_key_bob.point_key,
                                                   priv_key_bob.bn_key,
                                                   pub_key_alice.point_key,
                                                   capsule_alice)

    assert not pre._verify_correctness(capsule_alice, 
                                       cfrags[0], 
                                       pub_key_alice.point_key, 
                                       pub_key_bob.point_key,
                                      )

    # The response of cheating Ursula is in cfrags[0],
    # so the rest of CFrags chould be correct:
    for cfrag_i, metadata_i in zip(cfrags[1:], metadata[1:]):
        assert pre._verify_correctness(capsule_alice,
                                       cfrag_i,
                                       pub_key_alice.point_key,
                                       pub_key_bob.point_key,
                                      )

    # Alternatively, we can try to open the capsule directly.
    # We should get an exception with an attached list of incorrect cfrags
    with pytest.raises(pre.UmbralCorrectnessError) as exception_info:
        _ = pre._open_capsule(capsule_alice, priv_key_bob, pub_key_alice)
    correctness_error = exception_info.value
    assert cfrags[0] in correctness_error.offending_cfrags
    assert len(correctness_error.offending_cfrags) == 1

@pytest.mark.parametrize("N, M", parameters)
def test_decryption_fails_when_it_expects_a_proof_and_there_isnt(N, M, alices_keys, bobs_keys):

    """Manually injects umbralparameters for multi-curve testing."""

    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice, plain_data)

    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule, provide_proof=False)
        capsule.attach_cfrag(cfrag)


    with pytest.raises(AttributeError):
        _ = pre.decrypt(ciphertext, capsule, priv_key_bob, pub_key_alice)


@pytest.mark.parametrize("N, M", parameters)
def test_m_of_n(N, M, alices_keys, bobs_keys):
    priv_key_alice, pub_key_alice = alices_keys
    priv_key_bob, pub_key_bob = bobs_keys

    sym_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N)

    for kfrag in kfrags:
        assert kfrag.verify(pub_key_alice.point_key, pub_key_bob.point_key)

    for i, kfrag in enumerate(kfrags[:M]):

        # Example of potential metadata to describe the re-encryption request
        metadata = "This is an example of metadata for re-encryption request #{}"
        metadata = metadata.format(i).encode()

        cfrag = pre.reencrypt(kfrag, capsule, metadata=metadata)
        capsule.attach_cfrag(cfrag)

        assert pre._verify_correctness(capsule, cfrag,
                                       pub_key_alice.point_key, pub_key_bob.point_key,
                                      )

    # assert capsule.is_openable_by_bob()  # TODO: Is it possible to check here if >= m cFrags have been attached?
    
    sym_key_from_capsule = pre._open_capsule(capsule, priv_key_bob, pub_key_alice)
    assert sym_key == sym_key_from_capsule
