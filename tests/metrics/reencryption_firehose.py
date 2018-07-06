import os
import sys
from typing import Tuple, List

sys.path.append(os.path.abspath(os.getcwd()))

from umbral.fragments import KFrag
from umbral.pre import Capsule
from umbral import keys, pre
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer

CURVE = default_curve()
PARAMS = UmbralParameters(curve=CURVE)
REENCRYPTIONS = 1000


def __produce_kfrags_and_capsule(m: int, n: int) -> Tuple[List[KFrag], Capsule]:

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = os.urandom(32)
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, m, n)

    return kfrags, capsule


def firehose(m: int=6, n: int=10) -> None:

    print("Making kfrags...")
    kfrags, capsule = __produce_kfrags_and_capsule(m=m, n=n)
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


if __name__ == "__main__":
    firehose()  # do
