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

import pytest

from umbral import keys
from umbral import pre
from umbral.point import Point
from umbral.signing import Signer
from umbral.cfrags import CapsuleFrag


def test_cheating_ursula_replays_old_reencryption(alices_keys, bobs_keys,
                                                  kfrags, ciphertext_and_prepared_capsule, message):

    ciphertext, prepared_capsule = ciphertext_and_prepared_capsule

    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()

    receiving_privkey, receiving_pubkey = bobs_keys

    prepared_capsule_alice1 = prepared_capsule

    _unused_key2, capsule_alice2 = pre._encapsulate(delegating_pubkey)

    prepared_capsule_alice2 = capsule_alice2.with_correctness_keys(delegating=delegating_pubkey,
                                                                   receiving=receiving_pubkey,
                                                                   verifying=signing_privkey.get_pubkey())

    cfrags = []
    for i, kfrag in enumerate(kfrags):

        # Example of potential metadata to describe the re-encryption request
        metadata_i = "This is an example of metadata for re-encryption request #{}"
        metadata_i = metadata_i.format(i).encode()

        if i == 0:
            # Let's put the re-encryption of a different Alice ciphertext
            cfrag = pre.reencrypt(kfrag, prepared_capsule_alice2, metadata=metadata_i)
        else:
            cfrag = pre.reencrypt(kfrag, prepared_capsule_alice1, metadata=metadata_i)

        cfrags.append(cfrag)

    #  CFrag 0 is not valid ...
    assert not prepared_capsule_alice1.verify_cfrag(cfrags[0])

    # ... and trying to decrypt raises an error with it being listed as offending.
    with pytest.raises(pre.UmbralCorrectnessError) as exception_info:
        pre.decrypt_reencrypted(ciphertext, prepared_capsule_alice1, cfrags, receiving_privkey)

    correctness_error = exception_info.value
    assert cfrags[0] in correctness_error.offending_cfrags
    assert len(correctness_error.offending_cfrags) == 1 # The rest of CFrags should be correct

    # The rest of CFrags should be correct:
    for cfrag_i in cfrags[1:]:
        assert prepared_capsule_alice1.verify_cfrag(cfrag_i)

    # Decryption works without the offending cfrag
    cleartext = pre.decrypt_reencrypted(ciphertext, prepared_capsule_alice1, cfrags[1:], receiving_privkey)
    assert cleartext == message


def test_cheating_ursula_sends_garbage(kfrags, bobs_keys, ciphertext_and_prepared_capsule, message):
    ciphertext, prepared_capsule = ciphertext_and_prepared_capsule
    receiving_privkey, receiving_pubkey = bobs_keys

    cfrags = []
    for i, kfrag in enumerate(kfrags):
        # Example of potential metadata to describe the re-encryption request
        metadata_i = "This is an example of metadata for re-encryption request #{}"
        metadata_i = metadata_i.format(i).encode()

        cfrag = pre.reencrypt(kfrag, prepared_capsule, metadata=metadata_i)
        cfrags.append(cfrag)

    # Let's put random garbage in one of the cfrags
    cfrags[0].point_e1 = Point.gen_rand()
    cfrags[0].point_v1 = Point.gen_rand()

    #  Of course, this CFrag is not valid ...
    assert not prepared_capsule.verify_cfrag(cfrags[0])

    # ... and trying to decrypt raises an error with it being listed as offending.
    with pytest.raises(pre.UmbralCorrectnessError) as exception_info:
        pre.decrypt_reencrypted(ciphertext, prepared_capsule, cfrags, receiving_privkey)

    correctness_error = exception_info.value
    assert cfrags[0] in correctness_error.offending_cfrags
    assert len(correctness_error.offending_cfrags) == 1

    # The response of cheating Ursula is in cfrags[0],
    # so the rest of CFrags should be correct:
    for cfrag_i in cfrags[1:]:
        assert prepared_capsule.verify_cfrag(cfrag_i)

    cleartext = pre.decrypt_reencrypted(ciphertext, prepared_capsule, cfrags[1:], receiving_privkey)
    assert cleartext == message


def test_cfrag_with_missing_proof_cannot_be_verified(kfrags, prepared_capsule):

    cfrags = []
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, prepared_capsule)
        cfrags.append(cfrag)

    # If the proof is lost (e.g., it is chopped off a serialized CFrag or similar),
    #  then the CFrag cannot be attached.
    cfrags[0].proof = None
    with pytest.raises(CapsuleFrag.NoProofProvided):
        prepared_capsule.verify_cfrag(cfrags[0])

    # The remaining CFrags are fine, so they can be attached correctly
    for cfrag in cfrags[1:]:
        assert prepared_capsule.verify_cfrag(cfrag)


def test_kfrags_signed_without_correctness_keys(alices_keys, bobs_keys, capsule):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()
    verifying_key = signing_privkey.get_pubkey()

    receiving_privkey, receiving_pubkey = bobs_keys

    kfrags = pre.generate_kfrags(delegating_privkey=delegating_privkey,
                                 signer=Signer(signing_privkey),
                                 receiving_pubkey=receiving_pubkey,
                                 threshold=6,
                                 N=10,
                                 sign_delegating_key=False,
                                 sign_receiving_key=False)

    wrong_key = keys.UmbralPrivateKey.gen_key()
    wrong_pubkey = wrong_key.get_pubkey()

    # Even though this prepared capsule has wrong delegating and receiving keys,
    # it can still be used to verify a kfrag since we don't sign those keys.
    prepared_capsule = capsule.with_correctness_keys(verifying=verifying_key,
                                                     delegating=wrong_pubkey,
                                                     receiving=wrong_pubkey)

    for kfrag in kfrags:
        # You can verify the KFrag specifying only the verifying key
        assert kfrag.verify(signing_pubkey=verifying_key)

        # ... or if it is set in the capsule, using the capsule
        assert prepared_capsule.verify_kfrag(kfrag)

        # It should even work when other keys are set in the capsule
        assert kfrag.verify(signing_pubkey=verifying_key,
                            delegating_pubkey=delegating_pubkey,
                            receiving_pubkey=receiving_pubkey)
