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
from abc import abstractmethod, ABC
from typing import Optional, Type

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


class Hash(ABC):

    CUSTOMIZATION_STRING_LENGTH = 64
    CUSTOMIZATION_STRING_PAD = b'\x00'

    @abstractmethod
    def __init__(self, customization_string: bytes = b''):

        if len(customization_string) > Hash.CUSTOMIZATION_STRING_LENGTH:
            raise ValueError("The maximum length of the customization string is "
                             "{} bytes".format(Hash.CUSTOMIZATION_STRING_LENGTH))

        self.customization_string = customization_string.ljust(
            Hash.CUSTOMIZATION_STRING_LENGTH,
            Hash.CUSTOMIZATION_STRING_PAD
        )
        self.update(self.customization_string)

    @abstractmethod
    def update(self, data: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def copy(self) -> 'Hash':
        raise NotImplementedError

    @abstractmethod
    def finalize(self) -> bytes:
        raise NotImplementedError


class Blake2b(Hash):
    def __init__(self, customization_string: bytes = b''):
        # TODO: use a Blake2b implementation that supports personalization (see #155)
        self._blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=backend)
        super().__init__(customization_string)

    def update(self, data: bytes) -> None:
        self._blake2b.update(data)

    def copy(self) -> 'Blake2b':
        replica = type(self)()
        replica._blake2b = self._blake2b.copy()
        return replica

    def finalize(self) -> bytes:
        return self._blake2b.finalize()


class ExtendedKeccak(Hash):

    _UPPER_PREFIX = b'\x00'
    _LOWER_PREFIX = b'\x01'

    def __init__(self, customization_string: bytes = b''):
        self._upper = sha3.keccak_256()
        self._lower = sha3.keccak_256()

        self._upper.update(self._UPPER_PREFIX)
        self._lower.update(self._LOWER_PREFIX)

        super().__init__(customization_string)

    def update(self, data: bytes) -> None:
        self._upper.update(data)
        self._lower.update(data)

    def copy(self) -> 'ExtendedKeccak':
        replica = type(self)()
        replica._upper = self._upper.copy()
        replica._lower = self._lower.copy()
        return replica

    def finalize(self) -> bytes:
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
# TODO: ^ It should check the correct number and type args, instead of current approach.
def hash_to_curvebn(*crypto_items,
                    params: UmbralParameters,
                    customization_string: bytes = b'',
                    hash_class: Type[Hash] = Blake2b) -> CurveBN:

    customization_string = b'hash_to_curvebn' + customization_string
    hash_function = hash_class(customization_string=customization_string)

    for item in crypto_items:
        try:
            item_bytes = item.to_bytes()
        except AttributeError:
            if isinstance(item, bytes):
                item_bytes = item
            else:
                raise TypeError("Input with type {} not accepted".format(type(item)))
        hash_function.update(item_bytes)

    hash_digest = openssl._bytes_to_bn(hash_function.finalize())

    one = backend._lib.BN_value_one()

    order_minus_1 = openssl._get_new_BN()
    res = backend._lib.BN_sub(order_minus_1, params.curve.order, one)
    backend.openssl_assert(res == 1)

    bignum = openssl._get_new_BN()
    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod(bignum, hash_digest, order_minus_1, bn_ctx)
        backend.openssl_assert(res == 1)

    res = backend._lib.BN_add(bignum, bignum, one)
    backend.openssl_assert(res == 1)

    return CurveBN(bignum, params.curve)


def unsafe_hash_to_point(data: bytes = b'',
                         params: UmbralParameters = None,
                         label: bytes = b'',
                         hash_class = Blake2b,
                         ) -> 'Point':
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
        hash_function = hash_class()
        hash_function.update(label_data + ibytes)
        hash_digest = hash_function.finalize()[:1 + params.CURVE_KEY_SIZE_BYTES]

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
