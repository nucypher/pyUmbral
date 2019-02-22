"""
This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published b
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import hmac
from typing import Optional, Type

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA


from umbral.config import default_curve
from umbral.curve import Curve
from umbral.curvebn import CurveBN
from umbral.keys import UmbralPublicKey, UmbralPrivateKey


DEFAULT_HASH_ALGORITHM = SHA256


class Signature:
    """
    Wrapper for ECDSA signatures.
    We store signatures as r and s; this class allows interoperation
    between (r, s) and DER formatting.
    """

    def __init__(self,
                 r: CurveBN,
                 s: CurveBN,
                 hash_algorithm: Type[HashAlgorithm] = DEFAULT_HASH_ALGORITHM) -> None:
        self.r = r
        self.s = s
        self.hash_algorithm = hash_algorithm

    def __repr__(self):
        return "ECDSA Signature: {}".format(bytes(self).hex()[:15])

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None) -> int:
        curve = curve if curve is not None else default_curve()
        return 2 * curve.group_order_size_in_bytes

    def verify(self, message: bytes,
               verifying_key: UmbralPublicKey,
               is_prehashed: bool = False) -> bool:
        """
        Verifies that a message's signature was valid.

        :param message: The message to verify
        :param verifying_key: UmbralPublicKey of the signer
        :param is_prehashed: True if the message has been prehashed previously
        :return: True if valid, False if invalid
        """
        cryptography_pub_key = verifying_key.to_cryptography_pubkey()
        if is_prehashed:
            signature_algorithm = ECDSA(utils.Prehashed(self.hash_algorithm()))
        else:
            signature_algorithm = ECDSA(self.hash_algorithm())

        # TODO: Raise error instead of returning boolean
        try:
            cryptography_pub_key.verify(
                signature=self._der_encoded_bytes(),
                data=message,
                signature_algorithm=signature_algorithm
            )
        except InvalidSignature:
            return False
        return True

    @classmethod
    def from_bytes(cls,
                   signature_as_bytes: bytes,
                   der_encoded: bool = False,
                   curve: Optional[Curve] = None) -> 'Signature':
        curve = curve if curve is not None else default_curve()
        if der_encoded:
            r, s = utils.decode_dss_signature(signature_as_bytes)
        else:
            expected_len = cls.expected_bytes_length(curve)
            if not len(signature_as_bytes) == expected_len:
                raise ValueError("Looking for exactly {} bytes if you call from_bytes \
                    with der_encoded=False and curve={}.".format(expected_len, curve))
            else:
                r = int.from_bytes(signature_as_bytes[:(expected_len//2)], "big")
                s = int.from_bytes(signature_as_bytes[(expected_len//2):], "big")

        return cls(CurveBN.from_int(r, curve), CurveBN.from_int(s, curve))

    def _der_encoded_bytes(self) -> bytes:
        return utils.encode_dss_signature(int(self.r), int(self.s))

    def __bytes__(self) -> bytes:
        return self.r.to_bytes() + self.s.to_bytes()

    def __len__(self):
        return len(bytes(self))

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other: bytes) -> bytes:
        return other + bytes(self)

    def __eq__(self, other) -> bool:
        simple_bytes_match = hmac.compare_digest(bytes(self), bytes(other))
        der_encoded_match = hmac.compare_digest(self._der_encoded_bytes(), bytes(other))
        return simple_bytes_match or der_encoded_match


class Signer:
    """Callable wrapping ECDSA signing with UmbralPrivateKeys"""

    def __init__(self,
                 private_key: UmbralPrivateKey,
                 hash_algorithm: Type[HashAlgorithm] = DEFAULT_HASH_ALGORITHM) -> None:
        self.__cryptography_private_key = private_key.to_cryptography_privkey()
        self.curve = private_key.params.curve
        self.hash_algorithm = hash_algorithm

    def __call__(self, message: bytes, is_prehashed: bool = False) -> Signature:
        """
         Signs the message with this instance's private key.

         :param message: Message to hash and sign
         :param is_prehashed: True if the message has been prehashed previously
         :return: signature
         """
        if is_prehashed:
            signature_algorithm = ECDSA(utils.Prehashed(self.hash_algorithm()))
        else:
            signature_algorithm = ECDSA(self.hash_algorithm())

        signature_der_bytes = self.__cryptography_private_key.sign(message, signature_algorithm)
        return Signature.from_bytes(signature_der_bytes, der_encoded=True, curve=self.curve)
