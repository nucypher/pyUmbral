"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

from umbral import pre, keys
from umbral.config import default_curve
from umbral.fragments import KFrag, CapsuleFrag
from umbral.signing import Signer



def test_cfrag_serialization_with_proof_and_metadata(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()
    signer_alice = Signer(signing_privkey)
    _receiving_privkey, receiving_pubkey = bobs_keys


    _unused_key, capsule = pre._encapsulate(delegating_pubkey)
    kfrags = pre.split_rekey(delegating_privkey, signer_alice,
                             receiving_pubkey, 1, 2)

    # Example of potential metadata to describe the re-encryption request
    metadata = b'This is an example of metadata for re-encryption request'

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                     receiving=receiving_pubkey,
                                     verifying=signing_privkey.get_pubkey())

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True, metadata=metadata)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is not None

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof.bn_sig == proof.bn_sig
    assert new_proof.metadata == metadata
    assert new_proof.metadata == proof.metadata


def test_cfrag_serialization_with_proof_but_no_metadata(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()

    _receiving_privkey, receiving_pubkey = bobs_keys
    signer_alice = Signer(signing_privkey)

    _unused_key, capsule = pre._encapsulate(delegating_pubkey)
    kfrags = pre.split_rekey(delegating_privkey, signer_alice,
                             receiving_pubkey, 1, 2)

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=True)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is not None
    assert proof.metadata is None

    # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
    # TODO: Figure out final size for CFrags with proofs
    # assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is not None
    assert new_proof._point_e2 == proof._point_e2
    assert new_proof._point_v2 == proof._point_v2
    assert new_proof._point_kfrag_commitment == proof._point_kfrag_commitment
    assert new_proof._point_kfrag_pok == proof._point_kfrag_pok
    assert new_proof.bn_sig == proof.bn_sig
    assert new_proof.metadata is None


def test_cfrag_serialization_no_proof_no_metadata(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()

    _receiving_privkey, receiving_pubkey = bobs_keys
    signer_alice = Signer(signing_privkey)

    _unused_key, capsule = pre._encapsulate(delegating_pubkey)
    kfrags = pre.split_rekey(delegating_privkey, signer_alice,
                             receiving_pubkey, 1, 2)

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())

    cfrag = pre.reencrypt(kfrags[0], capsule, provide_proof=False)
    cfrag_bytes = cfrag.to_bytes()

    proof = cfrag.proof
    assert proof is None

    curve = default_curve()
    assert len(cfrag_bytes) == CapsuleFrag.expected_bytes_length(curve)

    new_cfrag = pre.CapsuleFrag.from_bytes(cfrag_bytes)
    assert new_cfrag._point_e1 == cfrag._point_e1
    assert new_cfrag._point_v1 == cfrag._point_v1
    assert new_cfrag._kfrag_id == cfrag._kfrag_id
    assert new_cfrag._point_noninteractive == cfrag._point_noninteractive

    new_proof = new_cfrag.proof
    assert new_proof is None
