from umbral.curvebn import CurveBN
from umbral.config import default_params
from umbral.params import UmbralParameters


def prove_cfrag_correctness(cfrag: "CapsuleFrag",
                            kfrag: "KFrag",
                            capsule: "Capsule",
                            metadata: bytes=None,
                            params: UmbralParameters=None
                      ) -> "CorrectnessProof":
    params = params if params is not None else default_params()

    rk = kfrag._bn_key
    t = CurveBN.gen_rand(params.curve)
    ####
    ## Here are the formulaic constituents shared with `assess_cfrag_correctness`.
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

    z1 = kfrag._bn_sig1
    z2 = kfrag._bn_sig2
    z3 = t + h * rk
    ########

    cfrag.attach_proof(e2, v2, u1, u2, z1, z2, z3, metadata)

    # Check correctness of original ciphertext (check nº 2) at the end
    # to avoid timing oracles
    if not capsule.verify(params):
        raise capsule.NotValid("Capsule verification failed.")


def assess_cfrag_correctness(cfrag,
                             capsule: "Capsule",
                             pubkey_a_point,
                             pubkey_b_point,
                             params: UmbralParameters = None):
    params = params if params is not None else default_params()

    ####
    ## Here are the formulaic constituents shared with `prove_cfrag_correctness`.
    ####
    e = capsule._point_e
    v = capsule._point_v

    e1 = cfrag._point_e1
    v1 = cfrag._point_v1

    u = params.u
    u1 = cfrag.proof._point_kfrag_commitment

    e2 = cfrag.proof._point_e2
    v2 = cfrag.proof._point_v2
    u2 = cfrag.proof._point_kfrag_pok

    hash_input = [e, e1, e2, v, v1, v2, u, u1, u2]
    if cfrag.proof.metadata is not None:
        hash_input.append(cfrag.proof.metadata)
    h = CurveBN.hash(*hash_input, params=params)

    z1 = cfrag.proof._bn_kfrag_sig1
    z2 = cfrag.proof._bn_kfrag_sig2
    z3 = cfrag.proof._bn_sig
    ########

    xcomp = cfrag._point_noninteractive
    kfrag_id = cfrag._kfrag_id

    g = params.g

    g_y = (z2 * g) + (z1 * pubkey_a_point)
    signature_input = [g_y, kfrag_id, pubkey_a_point, pubkey_b_point, u1, xcomp]
    kfrag_signature1 = CurveBN.hash(*signature_input, params=params)
    valid_kfrag_signature = z1 == kfrag_signature1

    correct_reencryption_of_e = z3 * e == e2 + (h * e1)

    correct_reencryption_of_v = z3 * v == v2 + (h * v1)

    correct_rk_commitment = z3 * u == u2 + (h * u1)

    return valid_kfrag_signature \
           & correct_reencryption_of_e \
           & correct_reencryption_of_v \
           & correct_rk_commitment


def verify_kfrag(kfrag,
                pubkey_a_point,
                pubkey_b_point,
                params: UmbralParameters = None
                ):

    params = params if params is not None else default_params()

    u = params.u

    u1 = kfrag._point_commitment
    z1 = kfrag._bn_sig1
    z2 = kfrag._bn_sig2
    x = kfrag._point_noninteractive
    key = kfrag._bn_key

    #  We check that the commitment u1 is well-formed
    correct_commitment = u1 == key * u

    # We check the Schnorr signature over the kfrag components
    g_y = (z2 * params.g) + (z1 * pubkey_a_point)

    kfrag_components = [g_y, kfrag._id, pubkey_a_point, pubkey_b_point, u1, x]
    valid_kfrag_signature = z1 == CurveBN.hash(*kfrag_components, params=params)

    return correct_commitment & valid_kfrag_signature
