import math
from abc import ABC, abstractmethod

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def lambda_coeff(id_i, selected_ids):
    ids = [x for x in selected_ids if x != id_i]

    if not ids:
        return None

    div_0 = ~(ids[0] - id_i)
    result = ids[0] * div_0
    for id_j in ids[1:]:
        div_j = ~(id_j - id_i)
        result = result * (id_j * div_j)

    return result


def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, -1):
        result = ((result * x) + coeff[i])

    return result


def kdf(ecpoint, key_length):
    data = ecpoint.to_bytes(is_compressed=True)

    return HKDF(
        algorithm=hashes.BLAKE2b(64),
        length=key_length,
        salt=None,
        info=None,
        backend=default_backend()
    ).derive(data)


def get_curve_keysize_bytes(curve):
    return int(math.ceil(curve.key_size / 8.00))


class AbstractCryptoEntity(ABC):
    @classmethod
    @abstractmethod
    def from_bytes(cls, *args, **kwargs):
        """
        Instantiate a split-key fragment object from the serialised data.
        """
        raise NotImplementedError("Derived classes should implement this method")

    @abstractmethod
    def to_bytes(self):
        """
        Serialize a split-key into a bytestring.
        """
        raise NotImplementedError("Derived classes should implement this method")

    def __bytes__(self):
        return self.to_bytes()
