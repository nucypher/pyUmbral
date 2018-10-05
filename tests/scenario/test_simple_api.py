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
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer
from umbral.keys import UmbralPrivateKey
from ..conftest import parameters, other_supported_curves


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(N, M, curve=default_curve()):
    """
    This test models the main interactions between NuCypher actors (i.e., Alice, 
    Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
    ciphertexts, capsules, KFrags, CFrags, etc). 

    The test covers all the main stages of data sharing with NuCypher:
    key generation, delegation, encryption, decryption by 
    Alice, re-encryption by Ursula, and decryption by Bob. 

    Manually injects umbralparameters for multi-curve testing."""

    # Generation of global parameters
    params = UmbralParameters(curve=curve)

    # Key Generation (Alice)
    delegating_privkey = UmbralPrivateKey.gen_key(params=params)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = UmbralPrivateKey.gen_key(params=params)
    signing_pubkey = signing_privkey.get_pubkey()
    signer = Signer(signing_privkey)

    # Key Generation (Bob)
    receiving_privkey = UmbralPrivateKey.gen_key(params=params)
    receiving_pubkey = receiving_privkey.get_pubkey()

    # Encryption by an unnamed data source
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    # Decryption by Alice
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data

    # Split Re-Encryption Key Generation (aka Delegation)
    kfrags = pre.generate_kfrags(delegating_privkey, receiving_pubkey, M, N, signer)


    # Capsule preparation (necessary before re-encryotion and activation)
    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_pubkey)

    # Bob requests re-encryption to some set of M ursulas
    cfrags = list()
    for kfrag in kfrags[:M]:
        # Ursula checks that the received kfrag is valid
        assert kfrag.verify(signing_pubkey, delegating_pubkey, receiving_pubkey, params)

        # Re-encryption by an Ursula
        cfrag = pre.reencrypt(kfrag, capsule)

        # Bob collects the result
        cfrags.append(cfrag)

    # Capsule activation (by Bob)
    for cfrag in cfrags:
        capsule.attach_cfrag(cfrag)

    # Decryption by Bob
    reenc_cleartext = pre.decrypt(ciphertext, capsule, receiving_privkey)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", other_supported_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    test_simple_api(N, M, curve)

