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
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import pre
from umbral.fragments import KFrag, CapsuleFrag
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from ..conftest import parameters, wrong_parameters, other_supported_curves


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""
    params = UmbralParameters(curve=curve)

    delegating_privkey = UmbralPrivateKey.gen_key(params=params)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = UmbralPrivateKey.gen_key(params=params)
    signing_pubkey = signing_privkey.get_pubkey()
    signer = Signer(signing_privkey)

    receiving_privkey = UmbralPrivateKey.gen_key(params=params)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_pubkey)

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, M, N)

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, receiving_privkey)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", other_supported_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    test_simple_api(N, M, curve)
    
