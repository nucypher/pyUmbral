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

from typing import Optional

from umbral.curvebn import CurveBN
from umbral.keys import UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.config import default_params


def prove_cfrag_correctness(cfrag: 'CapsuleFrag',
                            kfrag: 'KFrag',
                            capsule: 'Capsule',
                            metadata: Optional[bytes] = None
                            ) -> None:

    params = capsule.params

    # Check correctness of original ciphertext
    if not capsule.verify():
        raise capsule.NotValid("Capsule verification failed.")

    rk = kfrag._bn_key
    t = CurveBN.gen_rand(params.curve)
    ####
    # Here are the formulaic constituents shared with `assess_cfrag_correctness`.
    ####
    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    u = params.u
    u1 = kfrag._point_commitment

    e2 = t * e
    v2 = t * v
    u2 = t * u

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if metadata is not None:
        hash_input.append(metadata)
    h = CurveBN.hash(*hash_input, params=params)
    ########

    z3 = t + h * rk

    cfrag.attach_proof(e2, v2, u1, u2, metadata=metadata, z3=z3, kfrag_signature=kfrag.signature_for_bob)


def assess_cfrag_correctness(cfrag: 'CapsuleFrag', capsule: 'Capsule') -> bool:

    correctness_keys = capsule.get_correctness_keys()

    delegating_pubkey = correctness_keys['delegating']
    signing_pubkey = correctness_keys['verifying']
    receiving_pubkey = correctness_keys['receiving']

    params = capsule.params

    ####
    # Here are the formulaic constituents shared with `prove_cfrag_correctness`.
    ####
    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    u = params.u
    try:
        u1 = cfrag.proof._point_kfrag_commitment

        e2 = cfrag.proof._point_e2
        v2 = cfrag.proof._point_v2
        u2 = cfrag.proof._point_kfrag_pok
    except AttributeError:
        if cfrag.proof is None:
            raise cfrag.NoProofProvided
        else:
            raise

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if cfrag.proof.metadata is not None:
        hash_input.append(cfrag.proof.metadata)
    h = CurveBN.hash(*hash_input, params=params)
    ########

    precursor = cfrag._point_precursor
    kfrag_id = cfrag._kfrag_id

    validity_input = (kfrag_id, delegating_pubkey, receiving_pubkey, u1, precursor)

    kfrag_validity_message = bytes().join(bytes(item) for item in validity_input)
    valid_kfrag_signature = cfrag.proof.kfrag_signature.verify(kfrag_validity_message, signing_pubkey)

    z3 = cfrag.proof.bn_sig
    correct_reencryption_of_e = z3 * e == e2 + (h * e1)

    correct_reencryption_of_v = z3 * v == v2 + (h * v1)

    correct_rk_commitment = z3 * u == u2 + (h * u1)

    return valid_kfrag_signature \
           & correct_reencryption_of_e \
           & correct_reencryption_of_v \
           & correct_rk_commitment


def verify_kfrag(kfrag: 'KFrag',
                 params: UmbralParameters,
                 delegating_pubkey: Optional[UmbralPublicKey] = None,
                 signing_pubkey: Optional[UmbralPublicKey] = None,
                 receiving_pubkey: Optional[UmbralPublicKey] = None,
                 ) -> bool:

    if params is None:
        params = default_params()

    if delegating_pubkey and delegating_pubkey.params != params:
            raise ValueError("The delegating key uses different UmbralParameters")

    if receiving_pubkey and receiving_pubkey.params != params:
            raise ValueError("The receiving key uses different UmbralParameters")

    u = params.u

    kfrag_id = kfrag.id
    key = kfrag._bn_key
    commitment = kfrag._point_commitment
    precursor = kfrag._point_precursor

    #  We check that the commitment is well-formed
    correct_commitment = commitment == key * u
    validity_input = [kfrag_id, commitment, precursor, kfrag.keys_in_signature]

    if kfrag.delegating_key_in_signature():
        validity_input.append(delegating_pubkey)

    if kfrag.receiving_key_in_signature():
        validity_input.append(receiving_pubkey)

    kfrag_validity_message = bytes().join(bytes(item) for item in validity_input)
    valid_kfrag_signature = kfrag.signature_for_proxy.verify(kfrag_validity_message, signing_pubkey)

    return correct_commitment & valid_kfrag_signature
