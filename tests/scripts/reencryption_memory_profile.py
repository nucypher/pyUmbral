import os
import sys

sys.path.append(os.path.abspath(os.getcwd()))

from umbral import keys, pre
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer

CURVE = default_curve()
PARAMS = UmbralParameters(curve=CURVE)


def produce_kfrags(N, M):

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = os.urandom(32)
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, M, N)
    return kfrags, capsule


if __name__ == "__main__":

    _, reencryptions = sys.argv

    print("Making kfrags...")
    kfrags, capsule = produce_kfrags(6, 10)
    one_kfrag, *remaining_kfrags = kfrags

    print('Re-encrypting...')
    successful_rencryptions = 0
    for iteration in range(int(reencryptions)):
        cfrag = pre.reencrypt(one_kfrag, capsule)
        successful_rencryptions += 1
        if iteration % 20 == 0:
            print('Performed {} re-encryptions...'.format(iteration))

    print("Successfully performed {} reencryptions".format(successful_rencryptions), end='\n')