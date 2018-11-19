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
from umbral.keys import UmbralPrivateKey
from umbral.kfrags import KFrag


def test_set_correctness_keys(alices_keys, bobs_keys, capsule, kfrags):
    """
    If the three keys do appear together, along with the capsule,
    we can attach them all at once.
    """

    delegating_privkey, signing_privkey = alices_keys
    _receiving_privkey, receiving_pubkey = bobs_keys

    capsule.set_correctness_keys(delegating_privkey.get_pubkey(),
                                 receiving_pubkey,
                                 signing_privkey.get_pubkey()
                                 )

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule)
        capsule.attach_cfrag(cfrag)


def test_setting_one_correctness_keys(alices_keys, capsule):
    # The capsule doesn't have any correctness keys set initially
    assert capsule.get_correctness_keys()['delegating'] is None
    assert capsule.get_correctness_keys()['receiving'] is None
    assert capsule.get_correctness_keys()['verifying'] is None

    # Let's set only one of them, e.g., the delegating key
    delegating_privkey, _signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()

    details = capsule.set_correctness_keys(delegating=delegating_pubkey)

    # Since we are only setting the first key ("delegating"),
    # the other keys are not set
    assert details == (True, False, False)

    assert capsule.get_correctness_keys()['delegating'] == delegating_pubkey
    assert capsule.get_correctness_keys()['receiving'] is None
    assert capsule.get_correctness_keys()['verifying'] is None


def test_set_invalid_correctness_keys(alices_keys, capsule, kfrags):
    """
    If the three keys do appear together, along with the capsule,
    we can attach them all at once.
    """

    delegating_privkey, signing_privkey = alices_keys
    unrelated_receiving_pubkey = UmbralPrivateKey.gen_key().get_pubkey()

    capsule.set_correctness_keys(delegating_privkey.get_pubkey(),
                                 unrelated_receiving_pubkey,
                                 signing_privkey.get_pubkey()
                                 )

    for kfrag in kfrags:
        with pytest.raises(KFrag.NotValid):
            cfrag = pre.reencrypt(kfrag, capsule)
