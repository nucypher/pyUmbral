from umbral.curvebn import CurveBN
from umbral.config import default_params
from umbral.params import UmbralParameters


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

    kfrag_components = [g_y, kfrag._bn_id, pubkey_a_point, pubkey_b_point, u1, x]
    valid_kfrag_signature = z1 == CurveBN.hash(*kfrag_components, params=params)

    return correct_commitment & valid_kfrag_signature
