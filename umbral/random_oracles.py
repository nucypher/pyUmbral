"""
Copyright (C) 2018 NuCypher

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

from typing import Optional

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InternalError

import sha3

from umbral import openssl
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.params import UmbralParameters
from umbral.config import default_params


class Hash:

    def update(self, data: bytes): pass

    def copy(self): pass

    def finalize(self): pass


class Blake2b(Hash):
    def __init__(self):
        self._blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)

    def update(self, data: bytes):
        self._blake2b.update(data)

    def copy(self):
        replica = type(self)()
        replica._blake2b = self._blake2b.copy()
        return replica

    def finalize(self):
        return self._blake2b.finalize()


class ExtendedKeccak(Hash):

    _UPPER_PREFIX = b'\x00'
    _LOWER_PREFIX = b'\x01'

    def __init__(self):
        self._upper = sha3.keccak_256()
        self._lower = sha3.keccak_256()

        self._upper.update(self._UPPER_PREFIX)
        self._lower.update(self._LOWER_PREFIX)

    def update(self, data: bytes):
        self._upper.update(data)
        self._lower.update(data)

    def copy(self):
        replica = type(self)()
        replica._upper = self._upper.copy()
        replica._lower = self._lower.copy()
        return replica

    def finalize(self):
        return self._upper.digest() + self._lower.digest()


def kdf(ecpoint: Point,
        key_length: int,
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
        ) -> bytes:

    data = ecpoint.to_bytes(is_compressed=True)
    hkdf = HKDF(algorithm=hashes.BLAKE2b(64),
                length=key_length,
                salt=salt,
                info=info,
                backend=default_backend())
    return hkdf.derive(data)


# TODO: Common API for all hash_to_curvebn functions.
# Should check the correct number and type args, instead of current approach.

def hash_to_curvebn(*crypto_items, params: UmbralParameters) -> CurveBN:

    blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
    for item in crypto_items:
        try:
            item_bytes = item.to_bytes()
        except AttributeError:
            if isinstance(item, bytes):
                item_bytes = item
            else:
                raise TypeError("{} is not acceptable type, received {}".format(item, type(item)))
        blake2b.update(item_bytes)

    hash_digest = openssl._bytes_to_bn(blake2b.finalize())

    _1 = backend._lib.BN_value_one()

    order_minus_1 = openssl._get_new_BN()
    res = backend._lib.BN_sub(order_minus_1, params.curve.order, _1)
    backend.openssl_assert(res == 1)

    bignum = openssl._get_new_BN()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod(bignum, hash_digest, order_minus_1, bn_ctx)
        backend.openssl_assert(res == 1)

    res = backend._lib.BN_add(bignum, bignum, _1)
    backend.openssl_assert(res == 1)

    return CurveBN(bignum, params.curve)


def unsafe_hash_to_point(data : bytes = b'',
                         params: UmbralParameters = None,
                         label : bytes = b'') -> 'Point':
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.
    It admits an optional label as an additional input to the hash function.
    It uses BLAKE2b (with a digest size of 64 bytes) as the internal hash function.

    WARNING: Do not use when the input data is secret, as this implementation is not
    in constant time, and hence, it is not safe with respect to timing attacks.
    """

    params = params if params is not None else default_params()

    len_data = len(data).to_bytes(4, byteorder='big')
    len_label = len(label).to_bytes(4, byteorder='big')

    label_data = len_label + label + len_data + data

    # We use an internal 32-bit counter as additional input
    i = 0
    while i < 2**32:
        ibytes = i.to_bytes(4, byteorder='big')
        blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        blake2b.update(label_data + ibytes)
        hash_digest = blake2b.finalize()[:1 + params.CURVE_KEY_SIZE_BYTES]

        sign = b'\x02' if hash_digest[0] & 1 == 0 else b'\x03'
        compressed_point = sign + hash_digest[1:]

        try:
            return Point.from_bytes(compressed_point, params.curve)
        except InternalError as e:
            # We want to catch specific InternalExceptions:
            # - Point not in the curve (code 107)
            # - Invalid compressed point (code 110)
            # https://github.com/openssl/openssl/blob/master/include/openssl/ecerr.h#L228
            if e.err_code[0].reason in (107, 110):
                pass
            else:
                # Any other exception, we raise it
                raise e

        i += 1

    # Only happens with probability 2^(-32)
    raise ValueError('Could not hash input into the curve')
