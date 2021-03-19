import os
import time

import pytest

import umbral as umbral_py
import umbral_pre as umbral_rs


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


def __standard_encryption_api(umbral) -> tuple:

    delegating_sk = umbral.SecretKey.random()
    delegating_pk = umbral.PublicKey.from_secret_key(delegating_sk)

    signing_sk = umbral.SecretKey.random()

    receiving_sk = umbral.SecretKey.random()
    receiving_pk = umbral.PublicKey.from_secret_key(receiving_sk)

    plain_data = os.urandom(32)
    capsule, ciphertext = umbral.encrypt(delegating_pk, plain_data)

    return delegating_sk, receiving_pk, signing_sk, ciphertext, capsule


#
# KFrag Generation Benchmarks
#


@pytest.mark.benchmark(group="Reencryption Key Generation Performance",
                       disable_gc=True,
                       warmup=True,
                       warmup_iterations=10)
@pytest.mark.parametrize("m, n", FRAG_VALUES)
@pytest.mark.parametrize("umbral", [umbral_py, umbral_rs], ids=["python", "rust"])
def test_generate_kfrags_performance(benchmark, m: int, n: int, umbral) -> None:

    def __setup():
        delegating_sk, receiving_pk, signing_sk, ciphertext, capsule = __standard_encryption_api(umbral)
        return (delegating_sk, receiving_pk, signing_sk, m, n, True, True), {}

    benchmark.pedantic(umbral.generate_kfrags, setup=__setup, rounds=1000)
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
@pytest.mark.parametrize("umbral", [umbral_py, umbral_rs], ids=["python", "rust"])
def test_random_frag_reencryption_performance(benchmark, m: int, n: int, umbral) -> None:

    def __setup():
        delegating_sk, receiving_pk, signing_sk, ciphertext, capsule = __standard_encryption_api(umbral)
        kfrags = umbral.generate_kfrags(delegating_sk, receiving_pk, signing_sk, m, n, True, True)
        one_kfrag, *remaining_kfrags = kfrags
        return (capsule, one_kfrag), {}

    benchmark.pedantic(umbral.reencrypt, setup=__setup, rounds=1000)
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
@pytest.mark.parametrize("umbral", [umbral_py, umbral_rs], ids=["python", "rust"])
def test_single_frag_reencryption_performance(benchmark, m: int, n: int, umbral) -> None:

    delegating_sk, receiving_pk, signing_sk, ciphertext, capsule = __standard_encryption_api(umbral)
    kfrags = umbral.generate_kfrags(delegating_sk, receiving_pk, signing_sk, m, n, True, True)
    one_kfrag, *remaining_kfrags = kfrags
    args, kwargs = (capsule, one_kfrag), {}

    benchmark.pedantic(umbral.reencrypt, args=args, kwargs=kwargs, iterations=20, rounds=100)
    assert True  # ensure function finishes and succeeds.
