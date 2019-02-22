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

import sys
import os
import time

sys.path.append(os.path.abspath(os.getcwd()))


import pytest
from umbral import keys, pre
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer


#
# Setup
#


CURVE = default_curve()
PARAMS = UmbralParameters(curve=CURVE)

#                              Faster
#              (M, N)        # |
FRAG_VALUES = ((1, 1),       # |
               (2, 3),       # |
               (5, 8),       # |
               (6, 10),      # |
               (10, 30),     # |
               # (20, 30),   # |  # FIXME: CircleCi build killed
               # (10, 100)   # |
                             # |
               )             # |
#                              Slower


def __standard_encryption_api() -> tuple:

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=PARAMS)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = os.urandom(32)
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data)

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_privkey.get_pubkey())

    return delegating_privkey, signer, receiving_pubkey, ciphertext, capsule


#
# KFrag Generation Benchmarks
#


@pytest.mark.benchmark(group="Reencryption Key Generation Performance",
                       disable_gc=True,
                       warmup=True,
                       warmup_iterations=10)
@pytest.mark.parametrize("m, n", FRAG_VALUES)
def test_generate_kfrags_performance(benchmark, m: int, n: int) -> None:

    def __setup():
        delegating_privkey, signer, receiving_pubkey, ciphertext, capsule = __standard_encryption_api()
        args = (delegating_privkey, receiving_pubkey)
        kwargs = {"threshold": m, "N": n, "signer": signer}
        return args, kwargs

    print("\nBenchmarking {function} with M:{M} of N:{N}...".format(function="pre.generate_kfrags", M=m, N=n))
    benchmark.pedantic(pre.generate_kfrags, setup=__setup, rounds=1000)
    assert True  # ensure function finishes and succeeds.


#
# Reencryption Benchmarks
#

@pytest.mark.benchmark(group="Reencryption Performance",
                       timer=time.perf_counter,
                       disable_gc=True,
                       warmup=True,
                       warmup_iterations=10)
@pytest.mark.parametrize("m, n", ((6, 10), ))
def test_random_frag_reencryption_performance(benchmark, m: int, n: int) -> None:

    def __setup():
        delegating_privkey, signer, receiving_pubkey, ciphertext, capsule = __standard_encryption_api()
        kfrags = pre.generate_kfrags(delegating_privkey, receiving_pubkey, m, n, signer)
        one_kfrag, *remaining_kfrags = kfrags
        args, kwargs = tuple(), {"kfrag": one_kfrag, "capsule": capsule},
        return args, kwargs

    print("\nBenchmarking {} with randomly created fragments...".format("pre.reencrypt"))
    benchmark.pedantic(pre.reencrypt, setup=__setup, rounds=1000)
    assert True  # ensure function finishes and succeeds.


@pytest.mark.benchmark(group="Reencryption Performance",
                       timer=time.perf_counter,
                       disable_gc=True,
                       min_time=0.00005,
                       max_time=0.005,
                       min_rounds=7,
                       warmup=True,
                       warmup_iterations=10)
@pytest.mark.parametrize("m, n", ((6, 10), ))
def test_single_frag_reencryption_performance(benchmark, m: int, n: int) -> None:

    delegating_privkey, signer, receiving_pubkey, ciphertext, capsule = __standard_encryption_api()
    kfrags = pre.generate_kfrags(delegating_privkey, receiving_pubkey, m, n, signer)
    one_kfrag, *remaining_kfrags = kfrags
    args, kwargs = tuple(), {"kfrag": one_kfrag, "capsule": capsule},

    print("\nBenchmarking {} with the same fragment({M} of {N}) repeatedly...".format("pre.reencrypt", M=m, N=n))
    benchmark.pedantic(pre.reencrypt, args=args, kwargs=kwargs, iterations=20, rounds=100)
    assert True  # ensure function finishes and succeeds.
