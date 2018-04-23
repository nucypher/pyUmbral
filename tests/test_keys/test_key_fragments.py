from umbral import pre
import time


def test_kfrag_serialization(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)
    kfrag_bytes = kfrags[0].to_bytes()

    # A KFrag can be represented as the 194 total bytes of two Points (33 each) and four CurveBNs (32 each).
    assert len(kfrag_bytes) == 33 + 33 + (32 * 4) == 194

    new_frag = pre.KFrag.from_bytes(kfrag_bytes)
    assert new_frag._bn_id == kfrags[0]._bn_id
    assert new_frag._bn_key == kfrags[0]._bn_key
    assert new_frag._point_noninteractive == kfrags[0]._point_noninteractive
    assert new_frag._point_commitment == kfrags[0]._point_commitment
    assert new_frag._bn_sig1 == kfrags[0]._bn_sig1
    assert new_frag._bn_sig2 == kfrags[0]._bn_sig2


def test_cfrag_serialization_with_proof_and_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    # Example of potential metadata to describe the re-encryption request
    metadata = { 'ursula_id' : 42, 
                 'timestamp' : time.time(), 
                 'capsule' : bytes(capsule), 
               }
    metadata = str(metadata).encode()

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True, metadata=metadata)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is not None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
    # TODO: Figure out final size for CFrags with proofs
    #assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._bn_kfrag_id == cfrag._bn_kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof._bn_kfrag_sig1 == proof._bn_kfrag_sig1
    assert new_proof._bn_kfrag_sig2 == proof._bn_kfrag_sig2
    assert new_proof._bn_sig == proof._bn_sig
    assert new_proof.metadata == metadata
    assert new_proof.metadata == proof.metadata


def test_cfrag_serialization_with_proof_but_no_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
    # TODO: Figure out final size for CFrags with proofs
    #assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._bn_kfrag_id == cfrag._bn_kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof._bn_kfrag_sig1 == proof._bn_kfrag_sig1
    assert new_proof._bn_kfrag_sig2 == proof._bn_kfrag_sig2
    assert new_proof._bn_sig == proof._bn_sig
    assert new_proof.metadata is None

def test_cfrag_serialization_no_proof_no_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=False)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
    assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._bn_kfrag_id == cfrag._bn_kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is None
