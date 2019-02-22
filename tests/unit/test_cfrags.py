"""
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

from umbral import pre
from umbral.cfrags import CapsuleFrag, CorrectnessProof


def test_cfrag_serialization_with_proof_and_metadata(prepared_capsule, kfrags):

    # Example of potential metadata to describe the re-encryption request
    metadata = b'This is an example of metadata for re-encryption request'
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, prepared_capsule, provide_proof=True, metadata=metadata)
        cfrag_bytes = cfrag.to_bytes()

        proof = cfrag.proof
        assert proof is not None
        assert proof.metadata is not None

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)
        assert new_cfrag.point_e1 == cfrag.point_e1
        assert new_cfrag.point_v1 == cfrag.point_v1
        assert new_cfrag.kfrag_id == cfrag.kfrag_id
        assert new_cfrag.point_precursor == cfrag.point_precursor

        new_proof = new_cfrag.proof
        assert new_proof is not None
        assert new_proof.point_e2 == proof.point_e2
        assert new_proof.point_v2 == proof.point_v2
        assert new_proof.point_kfrag_commitment == proof.point_kfrag_commitment
        assert new_proof.point_kfrag_pok == proof.point_kfrag_pok
        assert new_proof.bn_sig == proof.bn_sig
        assert new_proof.metadata == metadata
        assert new_proof.metadata == proof.metadata


def test_cfrag_serialization_with_proof_but_no_metadata(prepared_capsule, kfrags):

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, prepared_capsule, provide_proof=True)
        cfrag_bytes = cfrag.to_bytes()

        proof = cfrag.proof
        assert proof is not None
        assert proof.metadata is None

        # A CFrag can be represented as the 131 total bytes of three Points (33 each) and a CurveBN (32).
        # TODO: Figure out final size for CFrags with proofs
        # assert len(cfrag_bytes) == 33 + 33 + 33 + 32 == 131

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)
        assert new_cfrag.point_e1 == cfrag.point_e1
        assert new_cfrag.point_v1 == cfrag.point_v1
        assert new_cfrag.kfrag_id == cfrag.kfrag_id
        assert new_cfrag.point_precursor == cfrag.point_precursor

        new_proof = new_cfrag.proof
        assert new_proof is not None
        assert new_proof.point_e2 == proof.point_e2
        assert new_proof.point_v2 == proof.point_v2
        assert new_proof.point_kfrag_commitment == proof.point_kfrag_commitment
        assert new_proof.point_kfrag_pok == proof.point_kfrag_pok
        assert new_proof.bn_sig == proof.bn_sig
        assert new_proof.metadata is None


def test_cfrag_serialization_no_proof_no_metadata(prepared_capsule, kfrags):
    
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, prepared_capsule, provide_proof=False)
        cfrag_bytes = cfrag.to_bytes()

        proof = cfrag.proof
        assert proof is None

        assert len(cfrag_bytes) == CapsuleFrag.expected_bytes_length()

        new_cfrag = CapsuleFrag.from_bytes(cfrag_bytes)
        assert new_cfrag.point_e1 == cfrag.point_e1
        assert new_cfrag.point_v1 == cfrag.point_v1
        assert new_cfrag.kfrag_id == cfrag.kfrag_id
        assert new_cfrag.point_precursor == cfrag.point_precursor

        new_proof = new_cfrag.proof
        assert new_proof is None


def test_correctness_proof_serialization(prepared_capsule, kfrags):
    
    # Example of potential metadata to describe the re-encryption request
    metadata = b"This is an example of metadata for re-encryption request"

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, prepared_capsule, metadata=metadata)
        proof = cfrag.proof
        proof_bytes = proof.to_bytes()

        # A CorrectnessProof can be represented as
        # the 228 total bytes of four Points (33 each) and three BigNums (32 each).
        # TODO: Figure out final size for CorrectnessProofs
        # assert len(proof_bytes) == (33 * 4) + (32 * 3) == 228

        new_proof = CorrectnessProof.from_bytes(proof_bytes)
        assert new_proof.point_e2 == proof.point_e2
        assert new_proof.point_v2 == proof.point_v2
        assert new_proof.point_kfrag_commitment == proof.point_kfrag_commitment
        assert new_proof.point_kfrag_pok == proof.point_kfrag_pok
        assert new_proof.bn_sig == proof.bn_sig
        assert new_proof.kfrag_signature == proof.kfrag_signature
        assert new_proof.metadata == proof.metadata

        