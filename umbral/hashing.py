from typing import TYPE_CHECKING, Optional, Iterable, Union, List, cast

from cryptography.hazmat.primitives import hashes

from .openssl import backend, ErrorInvalidCompressedPoint
from .curve import CURVE
from .curve_scalar import CurveScalar
from .curve_point import CurvePoint
from .serializable import Serializable, bool_bytes

if TYPE_CHECKING: # pragma: no cover
    from .key_frag import KeyFragID
    from .keys import PublicKey


class Hash:

    OUTPUT_SIZE = 32

    def __init__(self, dst: Optional[bytes] = None):
        self._backend_hash_algorithm = hashes.SHA256()
        self._hash = hashes.Hash(self._backend_hash_algorithm, backend=backend)

        if dst is not None:
            len_dst = len(dst).to_bytes(4, byteorder='big')
            self.update(len_dst + dst)

    def update(self, data: Union[bytes, Serializable]) -> None:
        self._hash.update(bytes(data))

    def finalize(self) -> bytes:
        return self._hash.finalize()


def hash_to_polynomial_arg(precursor: CurvePoint,
                           pubkey: CurvePoint,
                           dh_point: CurvePoint,
                           kfrag_id: 'KeyFragID',
                           ) -> CurveScalar:
    digest = Hash(b"POLYNOMIAL_ARG")
    digest.update(precursor)
    digest.update(pubkey)
    digest.update(dh_point)
    digest.update(kfrag_id)
    return CurveScalar.from_digest(digest)


def hash_capsule_points(e: CurvePoint, v: CurvePoint) -> CurveScalar:
    digest = Hash(b"CAPSULE_POINTS")
    digest.update(e)
    digest.update(v)
    return CurveScalar.from_digest(digest)


def hash_to_shared_secret(precursor: CurvePoint,
                          pubkey: CurvePoint,
                          dh_point: CurvePoint
                          ) -> CurveScalar:
    digest = Hash(b"SHARED_SECRET")
    digest.update(precursor)
    digest.update(pubkey)
    digest.update(dh_point)
    return CurveScalar.from_digest(digest)


def hash_to_cfrag_verification(points: Iterable[CurvePoint]) -> CurveScalar:
    digest = Hash(b"CFRAG_VERIFICATION")
    for point in points:
        digest.update(point)
    return CurveScalar.from_digest(digest)


def kfrag_signature_message(kfrag_id: 'KeyFragID',
                            commitment: CurvePoint,
                            precursor: CurvePoint,
                            maybe_delegating_pk: Optional['PublicKey'],
                            maybe_receiving_pk: Optional['PublicKey'],
                            ) -> bytes:

    # Have to convert to bytes manually because `mypy` is not smart enough to resolve types.

    delegating_part = ([bool_bytes(True), bytes(maybe_delegating_pk)]
                        if maybe_delegating_pk
                        else [bool_bytes(False)])
    cast(List[Serializable], delegating_part)

    receiving_part = ([bool_bytes(True), bytes(maybe_receiving_pk)]
                       if maybe_receiving_pk
                       else [bool_bytes(False)])

    components = ([bytes(kfrag_id), bytes(commitment), bytes(precursor)] +
                  delegating_part +
                  receiving_part)

    return b''.join(components)


def unsafe_hash_to_point(dst: bytes, data: bytes) -> CurvePoint:
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
        point_data = digest.finalize()[:CURVE.field_element_size]

        compressed_point = sign + point_data

        try:
            return CurvePoint.from_bytes(compressed_point)
        except ErrorInvalidCompressedPoint:
            # If it is not a valid point, continue on
            pass

    # Only happens with probability 2^(-32)
    raise ValueError('Could not hash input into the curve') # pragma: no cover
