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

from umbral import pre, keys
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.config import default_curve, default_params
from umbral.signing import Signer


def test_capsule_serialization(alices_keys):
    delegating_privkey, _signing_privkey = alices_keys
    params = delegating_privkey.params

    _symmetric_key, capsule = pre._encapsulate(delegating_privkey.get_pubkey())
    capsule_bytes = capsule.to_bytes()
    capsule_bytes_casted = bytes(capsule)
    assert capsule_bytes == capsule_bytes_casted

    # A Capsule can be represented as the 98 total bytes of two Points (33 each) and a CurveBN (32).
    assert len(capsule_bytes) == pre.Capsule.expected_bytes_length()

    new_capsule = pre.Capsule.from_bytes(capsule_bytes, params)

    # Three ways to think about equality.
    # First, the public approach for the Capsule.  Simply:
    assert new_capsule == capsule

    # Second, we show that the original components (which is all we have here since we haven't activated) are the same:
    assert new_capsule.original_components() == capsule.original_components()

    # Third, we can directly compare the private original component attributes
    # (though this is not a supported approach):
    assert new_capsule._point_e == capsule._point_e
    assert new_capsule._point_v == capsule._point_v
    assert new_capsule._bn_sig == capsule._bn_sig


def test_activated_capsule_serialization(alices_keys, bobs_keys):
    delegating_privkey, signing_privkey = alices_keys
    delegating_pubkey = delegating_privkey.get_pubkey()
    signer_alice = Signer(signing_privkey)

    params = delegating_privkey.params

    receiving_privkey, receiving_pubkey = bobs_keys

    _unused_key, capsule = pre._encapsulate(delegating_pubkey)

    
    kfrags = pre.split_rekey(delegating_privkey, signer_alice, receiving_pubkey, 1, 2)

    cfrag = pre.reencrypt(kfrags[0], capsule)

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())
    
    capsule.attach_cfrag(cfrag)

    capsule._reconstruct_shamirs_secret(receiving_privkey)
    rec_capsule_bytes = capsule.to_bytes()

    assert len(rec_capsule_bytes) == pre.Capsule.expected_bytes_length(activated=True)

    new_rec_capsule = pre.Capsule.from_bytes(rec_capsule_bytes, params)

    # Again, the same three perspectives on equality.
    assert new_rec_capsule == capsule

    assert new_rec_capsule.activated_components() == capsule.activated_components()

    assert new_rec_capsule._point_e_prime == capsule._point_e_prime
    assert new_rec_capsule._point_v_prime == capsule._point_v_prime
    assert new_rec_capsule._point_noninteractive == capsule._point_noninteractive


def test_cannot_create_capsule_from_bogus_material(alices_keys):
    params = alices_keys[0].params
    
    with pytest.raises(TypeError):
        capsule_of_questionable_parentage = pre.Capsule(params,
                                                        point_e=Point.gen_rand(),
                                                        point_v=42,
                                                        bn_sig=CurveBN.gen_rand())

    with pytest.raises(TypeError):
        capsule_of_questionable_parentage = pre.Capsule(params,
                                                        point_e=Point.gen_rand(),
                                                        point_v=Point.gen_rand(),
                                                        bn_sig=42)

    with pytest.raises(TypeError):
        capsule_of_questionable_parentage = pre.Capsule(params,
                                                        point_e_prime=Point.gen_rand(),
                                                        point_v_prime=42,
                                                        point_noninteractive=Point.gen_rand())

    with pytest.raises(TypeError):
        capsule_of_questionable_parentage = pre.Capsule(params,
                                                        point_e_prime=Point.gen_rand(),
                                                        point_v_prime=Point.gen_rand(),
                                                        point_noninteractive=42)
