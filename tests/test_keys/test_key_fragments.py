from umbral import pre
import time


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

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    # TODO: Figure out final size for CFrags with proofs
    #assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag.point_eph_e1 == cfrag.point_eph_e1
    assert new_cfrag.point_eph_v1 == cfrag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == cfrag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == cfrag.point_eph_ni

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof.point_eph_e2 == proof.point_eph_e2
    assert new_proof.point_eph_v2 == proof.point_eph_v2
    assert new_proof.point_kfrag_commitment == proof.point_kfrag_commitment
    assert new_proof.point_kfrag_pok == proof.point_kfrag_pok
    assert new_proof.bn_kfrag_sig1 == proof.bn_kfrag_sig1
    assert new_proof.bn_kfrag_sig2 == proof.bn_kfrag_sig2
    assert new_proof.bn_sig == proof.bn_sig
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

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    # TODO: Figure out final size for CFrags with proofs
    #assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag.point_eph_e1 == cfrag.point_eph_e1
    assert new_cfrag.point_eph_v1 == cfrag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == cfrag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == cfrag.point_eph_ni

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof.point_eph_e2 == proof.point_eph_e2
    assert new_proof.point_eph_v2 == proof.point_eph_v2
    assert new_proof.point_kfrag_commitment == proof.point_kfrag_commitment
    assert new_proof.point_kfrag_pok == proof.point_kfrag_pok
    assert new_proof.bn_kfrag_sig1 == proof.bn_kfrag_sig1
    assert new_proof.bn_kfrag_sig2 == proof.bn_kfrag_sig2
    assert new_proof.bn_sig == proof.bn_sig
    assert new_proof.metadata is None

def test_cfrag_serialization_no_proof_no_metadata(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys

    _unused_key, capsule = pre._encapsulate(pub_key_alice.point_key)
    kfrags = pre.split_rekey(priv_key_alice, pub_key_alice, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=False)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a BigNum (32).
    assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag.point_eph_e1 == cfrag.point_eph_e1
    assert new_cfrag.point_eph_v1 == cfrag.point_eph_v1
    assert new_cfrag.bn_kfrag_id == cfrag.bn_kfrag_id
    assert new_cfrag.point_eph_ni == cfrag.point_eph_ni

    new_proof = new_cfrag.proof
    assert new_proof is None
