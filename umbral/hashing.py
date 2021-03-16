from typing import Optional, Type

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InternalError

from . import openssl
from .curve import CURVE
from .curve_scalar import CurveScalar
from .curve_point import CurvePoint


class Hash:
    def __init__(self, dst: bytes):
        self._sha256 = hashes.Hash(hashes.SHA256(), backend=backend)
        len_dst = len(dst).to_bytes(4, byteorder='big')
        self.update(len_dst + dst)

    def update(self, data: bytes) -> None:
        self._sha256.update(data)

    def finalize(self) -> bytes:
        return self._sha256.finalize()


def unsafe_hash_to_point(dst: bytes, data: bytes) -> 'Point':
    """
    Hashes arbitrary data into a valid EC point of the specified curve,
    using the try-and-increment method.

    WARNING: Do not use when the input data is secret, as this implementation is not
    in constant time, and hence, it is not safe with respect to timing attacks.
    """

    len_data = len(data).to_bytes(4, byteorder='big')
    data_with_len = len_data + data
    sign = b'\x02'

    # We use an internal 32-bit counter as additional input
    for i in range(2**32):
        ibytes = i.to_bytes(4, byteorder='big')
        digest = Hash(dst)
        digest.update(data_with_len + ibytes)
        point_data = digest.finalize()[:CURVE.field_order_size_in_bytes]

        compressed_point = sign + point_data

        try:
            return CurvePoint.from_bytes(compressed_point)
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

    # Only happens with probability 2^(-32)
    raise ValueError('Could not hash input into the curve') # pragma: no cover
