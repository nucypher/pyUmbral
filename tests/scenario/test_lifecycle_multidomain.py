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

import pytest

from umbral import pre
from umbral.cfrags import CapsuleFrag
from umbral.kfrags import KFrag
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from ..conftest import parameters, other_supported_curves, kfrag_signing_modes


@pytest.mark.parametrize("N, M", parameters)
@pytest.mark.parametrize("signing_mode", kfrag_signing_modes)
def test_lifecycle_with_serialization(N, M, signing_mode, curve=default_curve()):
    """
    This test is a variant of test_simple_api, but with intermediate 
    serialization/deserialization steps, modeling how pyUmbral artifacts 
    (such as keys, ciphertexts, etc) will actually be used. 
    These intermediate steps are in between the different 'usage domains' 
    in NuCypher, namely, key generation, delegation, encryption, decryption by 
    Alice, re-encryption by Ursula, and decryption by Bob. 

    Manually injects UmbralParameters for multi-curve testing.
    """

    # Convenience method to avoid replicating key generation code
    def new_keypair_bytes():
        privkey = UmbralPrivateKey.gen_key(params=params)
        return privkey.to_bytes(), privkey.get_pubkey().to_bytes()

    ## SETUP
    params = UmbralParameters(curve=curve)

    delegating_privkey_bytes, delegating_pubkey_bytes = new_keypair_bytes()
    signing_privkey_bytes, signing_pubkey_bytes = new_keypair_bytes()
    receiving_privkey_bytes, receiving_pubkey_bytes = new_keypair_bytes()

    ## DELEGATION DOMAIN:
    ## Alice delegates decryption rights to some Bob by generating a set of 
    ## KFrags, using her delegating private key and Bob's receiving public key

    delegating_privkey = UmbralPrivateKey.from_bytes(delegating_privkey_bytes, params=params)
    signing_privkey = UmbralPrivateKey.from_bytes(signing_privkey_bytes, params=params)
    receiving_pubkey = UmbralPublicKey.from_bytes(receiving_pubkey_bytes, params=params)

    signer = Signer(signing_privkey)

    sign_delegating_key, sign_receiving_key = signing_mode

    kfrags = pre.generate_kfrags(delegating_privkey=delegating_privkey,
                                 receiving_pubkey=receiving_pubkey,
                                 threshold=M,
                                 N=N,
                                 signer=signer,
                                 sign_delegating_key=sign_delegating_key,
                                 sign_receiving_key=sign_receiving_key)

    kfrags_bytes = tuple(map(bytes, kfrags))

    del kfrags
    del signer
    del delegating_privkey
    del signing_privkey
    del receiving_pubkey
    del params

    ## ENCRYPTION DOMAIN ##

    params = UmbralParameters(curve=curve)

    delegating_pubkey = UmbralPublicKey.from_bytes(delegating_pubkey_bytes, params)

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)
    capsule_bytes = bytes(capsule)
    
    del capsule
    del delegating_pubkey
    del params

    ## DECRYPTION BY ALICE ##

    params = UmbralParameters(curve=curve)

    delegating_privkey = UmbralPrivateKey.from_bytes(delegating_privkey_bytes, params=params)
    capsule = pre.Capsule.from_bytes(capsule_bytes, params)
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data

    del delegating_privkey
    del capsule
    del params

    ## RE-ENCRYPTION DOMAIN (i.e., Ursula's side)

    cfrags_bytes = list()
    for kfrag_bytes in kfrags_bytes:
        params = UmbralParameters(curve=curve)
        delegating_pubkey = UmbralPublicKey.from_bytes(delegating_pubkey_bytes, params)
        signing_pubkey = UmbralPublicKey.from_bytes(signing_pubkey_bytes, params)
        receiving_pubkey = UmbralPublicKey.from_bytes(receiving_pubkey_bytes, params)

        capsule = pre.Capsule.from_bytes(capsule_bytes, params)
        capsule.set_correctness_keys(delegating=delegating_pubkey,
                                     receiving=receiving_pubkey,
                                     verifying=signing_pubkey)

        # TODO: use params instead of curve?
        kfrag = KFrag.from_bytes(kfrag_bytes, params.curve)

        assert kfrag.verify(signing_pubkey, delegating_pubkey, receiving_pubkey, params)

        cfrag_bytes = bytes(pre.reencrypt(kfrag, capsule))
        cfrags_bytes.append(cfrag_bytes)

        del capsule
        del kfrag
        del params
        del delegating_pubkey
        del signing_pubkey
        del receiving_pubkey

    ## DECRYPTION DOMAIN (i.e., Bob's side)
    params = UmbralParameters(curve=curve)

    capsule = pre.Capsule.from_bytes(capsule_bytes, params)
    delegating_pubkey = UmbralPublicKey.from_bytes(delegating_pubkey_bytes, params)
    signing_pubkey = UmbralPublicKey.from_bytes(signing_pubkey_bytes, params)
    receiving_privkey = UmbralPrivateKey.from_bytes(receiving_privkey_bytes, params=params)
    receiving_pubkey = receiving_privkey.get_pubkey()

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_pubkey)

    for cfrag_bytes in cfrags_bytes:
        # TODO: use params instead of curve?
        cfrag = CapsuleFrag.from_bytes(cfrag_bytes, params.curve)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, receiving_privkey)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", other_supported_curves)
@pytest.mark.parametrize("N, M", parameters)
@pytest.mark.parametrize("signing_mode", kfrag_signing_modes)
def test_lifecycle_with_serialization_on_multiple_curves(N, M, signing_mode, curve):
    test_lifecycle_with_serialization(N, M, signing_mode, curve)
