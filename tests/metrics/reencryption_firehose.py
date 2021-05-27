import os
import sys

sys.path.append(os.path.abspath(os.getcwd()))

from typing import Tuple, List

import umbral


REENCRYPTIONS = 1000


def __produce_kfrags_and_capsule(m: int, n: int) -> Tuple[List[umbral.KeyFrag], umbral.Capsule]:

    delegating_sk = umbral.SecretKey.random()
    delegating_pk = umbral.PublicKey.from_secret_key(delegating_sk)

    signing_sk = umbral.SecretKey.random()

    receiving_sk = umbral.SecretKey.random()
    receiving_pk = umbral.PublicKey.from_secret_key(receiving_sk)

    plain_data = os.urandom(32)
    capsule, ciphertext = umbral.encrypt(delegating_pk, plain_data)

    kfrags = umbral.generate_kfrags(delegating_sk, receiving_pk, signing_sk, m, n)

    return kfrags, capsule


def firehose(m: int=6, n: int=10) -> None:

    print("Making kfrags...")
    kfrags, capsule = __produce_kfrags_and_capsule(m=m, n=n)
    one_kfrag, *remaining_kfrags = kfrags

    print('Re-encrypting...')
    successful_reencryptions = 0
    for iteration in range(int(REENCRYPTIONS)):

        _cfrag = umbral.reencrypt(capsule, one_kfrag)    # <<< REENCRYPTION HAPPENS HERE

        successful_reencryptions += 1
        if iteration % 20 == 0:
            print('Performed {} Re-encryptions...'.format(iteration))

    failure_message = "A Reencryption failed. {} of {} succeeded".format(successful_reencryptions, REENCRYPTIONS)
    assert successful_reencryptions == REENCRYPTIONS, failure_message
    print("Successfully performed {} reencryptions".format(successful_reencryptions), end='\n')


if __name__ == "__main__":
    firehose()  # do
