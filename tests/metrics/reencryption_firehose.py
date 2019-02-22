"""
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

import os
import sys
from typing import Tuple, List

sys.path.append(os.path.abspath(os.getcwd()))

from umbral.kfrags import KFrag
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

    kfrags = pre.generate_kfrags(delegating_privkey, receiving_pubkey, m, n, signer)

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())

    return kfrags, capsule


def firehose(m: int=6, n: int=10) -> None:

    print("Making kfrags...")
    kfrags, capsule = __produce_kfrags_and_capsule(m=m, n=n)
    one_kfrag, *remaining_kfrags = kfrags

    print('Re-encrypting...')
    successful_reencryptions = 0
    for iteration in range(int(REENCRYPTIONS)):

        _cfrag = pre.reencrypt(one_kfrag, capsule)    # <<< REENCRYPTION HAPPENS HERE

        successful_reencryptions += 1
        if iteration % 20 == 0:
            print('Performed {} Re-encryptions...'.format(iteration))

    failure_message = "A Reencryption failed. {} of {} succeeded".format(successful_reencryptions, REENCRYPTIONS)
    assert successful_reencryptions == REENCRYPTIONS, failure_message
    print("Successfully performed {} reencryptions".format(successful_reencryptions), end='\n')


if __name__ == "__main__":
    firehose()  # do
