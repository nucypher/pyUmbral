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
from umbral.signing import Signer
from ..conftest import wrong_parameters

def test_public_key_encryption(alices_keys):
    delegating_privkey, _ = alices_keys
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data)
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data

@pytest.mark.parametrize("N, M", wrong_parameters)
def test_wrong_N_M_in_split_rekey(N, M, alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    signer = Signer(signing_privkey)
    _receiving_privkey, receiving_pubkey = bobs_keys

    with pytest.raises(ValueError):
        _kfrags = pre.generate_kfrags(delegating_privkey=delegating_privkey,
                                      signer=signer,
                                      receiving_pubkey=receiving_pubkey,
                                      threshold=M,
                                      N=N)

