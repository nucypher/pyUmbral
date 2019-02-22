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

from umbral.kfrags import KFrag


def test_kfrag_serialization(alices_keys, bobs_keys, kfrags):
    
    delegating_privkey, signing_privkey = alices_keys
    _receiving_privkey, receiving_pubkey = bobs_keys

    for kfrag in kfrags:
        kfrag_bytes = kfrag.to_bytes()
        assert len(kfrag_bytes) == KFrag.expected_bytes_length()

        new_kfrag = KFrag.from_bytes(kfrag_bytes)
        assert new_kfrag.id == kfrag.id
        assert new_kfrag.bn_key == kfrag.bn_key
        assert new_kfrag.point_precursor == kfrag.point_precursor
        assert new_kfrag.point_commitment == kfrag.point_commitment
        assert new_kfrag.keys_in_signature == kfrag.keys_in_signature
        assert new_kfrag.signature_for_proxy == kfrag.signature_for_proxy
        assert new_kfrag.signature_for_bob == kfrag.signature_for_bob

        assert new_kfrag.verify(signing_pubkey=signing_privkey.get_pubkey(),
                                delegating_pubkey=delegating_privkey.get_pubkey(),
                                receiving_pubkey=receiving_pubkey)

        assert new_kfrag == kfrag


def test_kfrag_verify_for_capsule(prepared_capsule, kfrags):
    for kfrag in kfrags:
        assert kfrag.verify_for_capsule(prepared_capsule)

        # If we alter some element, the verification fails
        previous_id, kfrag.id = kfrag.id, bytes(32)
        assert not kfrag.verify_for_capsule(prepared_capsule)    

        # Let's restore the KFrag, and alter the re-encryption key instead
        kfrag.id = previous_id
        kfrag.bn_key += kfrag.bn_key
        assert not kfrag.verify_for_capsule(prepared_capsule)    


def test_kfrag_as_dict_key(kfrags):
    dict_with_kfrags_as_keys = dict()
    dict_with_kfrags_as_keys[kfrags[0]] = "Some llamas.  Definitely some llamas."
    dict_with_kfrags_as_keys[kfrags[1]] = "No llamas here.  Definitely not."

    assert dict_with_kfrags_as_keys[kfrags[0]] != dict_with_kfrags_as_keys[kfrags[1]]


