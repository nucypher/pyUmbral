import os
import sys

sys.path.append(os.path.abspath(os.getcwd()))

from umbral import keys, pre
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer

CURVE = default_curve()
PARAMS = UmbralParameters(curve=CURVE)
REENCRYPTIONS = 1000


def __produce_kfrags(M, N) -> list:

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    receiving_pubkey = receiving_privkey.get_pubkey()

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, M, N)
    return kfrags


def firehose() -> None:

    print("Making kfrags...")
    kfrags, capsule = __produce_kfrags(M=6, N=10)
    one_kfrag, *remaining_kfrags = kfrags

    print('Re-encrypting...')
    successful_rencryptions = 0
    for iteration in range(int(REENCRYPTIONS)):

        _cfrag = pre.reencrypt(one_kfrag, capsule)    # <<< REENCRYPTION HAPPENS HERE

        successful_rencryptions += 1
        if iteration % 20 == 0:
            print('Performed {} Re-encryptions...'.format(iteration))

    failure_message = "A Reencryption failed. {} of {} succeeded".format(successful_rencryptions, REENCRYPTIONS)
    assert successful_rencryptions == REENCRYPTIONS, failure_message
    print("Successfully performed {} reencryptions".format(successful_rencryptions), end='\n')
