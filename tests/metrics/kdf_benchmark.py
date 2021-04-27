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
import time

from passlib.hash import argon2, pbkdf2_sha512, scrypt, bcrypt_sha256

from umbral.keys import Scrypt

sys.path.append(os.path.abspath(os.getcwd()))

import pytest

# Reference for values: https://tools.ietf.org/html/rfc7914#section-2
SCRYPT_COST_INTERACTIVE = 14
SCRYPT_COST_SENSITIVE = 20


def run_argon2(password, salt):
    argon2.using(
        salt=salt,
        rounds=2,
        type='ID'
    ).hash(password)


def run_scrypt_interactive(password, salt):
    Scrypt()(
        password=password,
        salt=salt,
        _scrypt_cost=SCRYPT_COST_INTERACTIVE
    )


def run_scrypt_sensitive(password, salt):
    Scrypt()(
        password=password,
        salt=salt,
        _scrypt_cost=SCRYPT_COST_SENSITIVE
    )


def run_passlib_scrypt_interactive(password, salt):
    scrypt.using(
        salt=salt,
        rounds=SCRYPT_COST_INTERACTIVE
    ).hash(password)


def run_passlib_scrypt_sensitive(password, salt):
    scrypt.using(
        salt=salt,
        rounds=SCRYPT_COST_SENSITIVE
    ).hash(password)


def run_bcrypt(password, salt):
    bcrypt_sha256.using(
        # salt=salt, # generate salt
        rounds=12
    ).hash(password)


def run_pbkdf2_sha512(password, salt):
    pbkdf2_sha512.using(
        salt=salt,
        rounds=100_000
    ).hash(password)


ALGOS = [
    run_argon2,
    run_passlib_scrypt_interactive,
    run_passlib_scrypt_sensitive,
    run_scrypt_interactive,
    run_scrypt_sensitive,
    run_bcrypt,
    run_pbkdf2_sha512
]


@pytest.mark.benchmark(group="KDF - Algos",
                       timer=time.perf_counter,
                       disable_gc=True,
                       warmup=True,
                       warmup_iterations=5)
@pytest.mark.parametrize("func", ALGOS)
def test_kdf_algos_benchmark(benchmark, func) -> None:
    args, kwargs = tuple(), {'salt': b'salt-salt', 'password': b'password'}
    benchmark.pedantic(func, args=args, kwargs=kwargs, iterations=5, rounds=10)
    assert True  # ensure function finishes and succeeds.
