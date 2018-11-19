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

import os
from typing import Callable, Optional, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey, _EllipticCurvePublicKey
from cryptography.exceptions import InternalError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as CryptographyScrypt
from nacl.secret import SecretBox

from umbral import openssl
from umbral.config import default_params
from umbral.curvebn import CurveBN
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.curve import Curve
from umbral.random_oracles import hash_to_curvebn


__SALT_SIZE = 32


class Scrypt:
    __DEFAULT_SCRYPT_COST = 20

    def __call__(self,
                 password: bytes,
                 salt: bytes,
                 **kwargs) -> bytes:
        """
        Derives a symmetric encryption key from a pair of password and salt.
        It also accepts an additional _scrypt_cost argument.
        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. It is NOT recommended to change the `_scrypt_cost` value unless
        you know what you are doing.
        :param password: byte-encoded password used to derive a symmetric key
        :param salt: cryptographic salt added during key derivation
        :return:
        """

        _scrypt_cost = kwargs.get('_scrypt_cost', Scrypt.__DEFAULT_SCRYPT_COST)
        try:
            derived_key = CryptographyScrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2 ** _scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)
        except InternalError as e:
            required_memory = 128 * 2**_scrypt_cost * 8 // (10**6)
            if e.err_code[0].reason == 65:
                raise MemoryError(
                    "Scrypt key derivation requires at least {} MB of memory. "
                    "Please free up some memory and try again.".format(required_memory)
                )
            else:
                raise e
        else:
            return derived_key


def derive_key_from_password(password: bytes,
                             salt: bytes,
                             **kwargs) -> bytes:
    """
    Derives a symmetric encryption key from a pair of password and salt.
    It uses Scrypt by default.
    """
    kdf = kwargs.get('kdf', Scrypt)()
    derived_key = kdf(password, salt, **kwargs)
    return derived_key


def wrap_key(key_to_wrap: bytes,
             wrapping_key: Optional[bytes] = None,
             password: Optional[bytes] = None,
             **kwargs) -> bytes:
    """
    Wraps a key using a provided wrapping key. Alternatively, it can derive
    the wrapping key from a password.
    :param key_to_wrap:
    :param wrapping_key:
    :param password:
    :return:
    """
    if not(bool(password) ^ bool(wrapping_key)):
        raise ValueError("Either password or wrapping_key must be passed")

    wrapped_key = b''
    if password:
        salt = os.urandom(__SALT_SIZE)
        wrapping_key = derive_key_from_password(password=password,
                                                salt=salt,
                                                **kwargs)
        wrapped_key = salt

    wrapped_key += SecretBox(wrapping_key).encrypt(key_to_wrap)
    return wrapped_key


def unwrap_key(wrapped_key: bytes,
               wrapping_key: Optional[bytes] = None,
               password: Optional[bytes] = None,
               **kwargs) -> bytes:
    """
    Unwraps a key using a provided wrapping key. Alternatively, it can derive
    the wrapping key from a password.
    :param wrapped_key:
    :param wrapping_key:
    :param password:
    :return:
    """
    if all((password, wrapping_key)) or not any((password, wrapping_key)):
        raise ValueError("Either password or wrapping_key must be passed")

    if password:
        salt = wrapped_key[:__SALT_SIZE]
        wrapped_key = wrapped_key[__SALT_SIZE:]
        wrapping_key = derive_key_from_password(password=password,
                                                salt=salt,
                                                **kwargs)

    key = SecretBox(wrapping_key).decrypt(wrapped_key)
    return key


class UmbralPrivateKey:
    def __init__(self, bn_key: CurveBN, params: UmbralParameters) -> None:
        """
        Initializes an Umbral private key.
        """
        self.params = params
        self.bn_key = bn_key
        self.pubkey = UmbralPublicKey(self.bn_key * params.g, params=params)  # type: ignore

    @classmethod
    def gen_key(cls, params: Optional[UmbralParameters] = None) -> 'UmbralPrivateKey':
        """
        Generates a private key and returns it.
        """
        if params is None:
            params = default_params()

        bn_key = CurveBN.gen_rand(params.curve)
        return cls(bn_key, params)

    @classmethod
    def from_bytes(cls,
                   key_bytes: bytes,
                   wrapping_key: Optional[bytes] = None,
                   password: Optional[bytes] = None,
                   params: Optional[UmbralParameters] = None,
                   decoder: Optional[Callable] = None,
                   **kwargs) -> 'UmbralPrivateKey':
        """
        Loads an Umbral private key from bytes.
        Optionally, allows a decoder function to be passed as a param to decode
        the data provided before converting to an Umbral key.
        Optionally, uses a wrapping key to unwrap an encrypted Umbral private key.
        Alternatively, if a password is provided it will derive the wrapping key
        from it.
        """
        if params is None:
            params = default_params()

        if decoder:
            key_bytes = decoder(key_bytes)

        if any((wrapping_key, password)):
            key_bytes = unwrap_key(wrapped_key=key_bytes,
                                   wrapping_key=wrapping_key,
                                   password=password,
                                   **kwargs)

        bn_key = CurveBN.from_bytes(key_bytes, params.curve)
        return cls(bn_key, params)

    def to_bytes(self,
                 wrapping_key: Optional[bytes] = None,
                 password: Optional[bytes] = None,
                 encoder: Optional[Callable] = None,
                 **kwargs) -> bytes:
        """
        Returns an UmbralPrivateKey as bytes with optional symmetric
        encryption via nacl's Salsa20-Poly1305.
        If a password is provided instead of a wrapping key, it will use
        Scrypt for key derivation.
        Optionally, allows an encoder to be passed in as a param to encode the
        data before returning it.
        """

        key_bytes = self.bn_key.to_bytes()

        if wrapping_key or password:
            key_bytes = wrap_key(key_to_wrap=key_bytes,
                                 wrapping_key=wrapping_key,
                                 password=password,
                                 **kwargs)

        if encoder:
            key_bytes = encoder(key_bytes)

        return key_bytes

    def get_pubkey(self) -> 'UmbralPublicKey':
        """
        Calculates and returns the public key of the private key.
        """
        return self.pubkey

    def to_cryptography_privkey(self) -> _EllipticCurvePrivateKey:
        """
        Returns a cryptography.io EllipticCurvePrivateKey from the Umbral key.
        """
        backend = default_backend()

        backend.openssl_assert(self.bn_key.curve.ec_group != backend._ffi.NULL)
        backend.openssl_assert(self.bn_key.bignum != backend._ffi.NULL)

        ec_key = backend._lib.EC_KEY_new()
        backend.openssl_assert(ec_key != backend._ffi.NULL)
        ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

        set_group_result = backend._lib.EC_KEY_set_group(
            ec_key, self.bn_key.curve.ec_group
        )
        backend.openssl_assert(set_group_result == 1)

        set_privkey_result = backend._lib.EC_KEY_set_private_key(
            ec_key, self.bn_key.bignum
        )
        backend.openssl_assert(set_privkey_result == 1)

        # Get public key
        point = openssl._get_new_EC_POINT(self.params.curve)
        with backend._tmp_bn_ctx() as bn_ctx:
            mult_result = backend._lib.EC_POINT_mul(
                self.bn_key.curve.ec_group, point, self.bn_key.bignum,
                backend._ffi.NULL, backend._ffi.NULL, bn_ctx
            )
            backend.openssl_assert(mult_result == 1)

        set_pubkey_result = backend._lib.EC_KEY_set_public_key(ec_key, point)
        backend.openssl_assert(set_pubkey_result == 1)

        evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
        return _EllipticCurvePrivateKey(backend, ec_key, evp_pkey)


class UmbralPublicKey:
    def __init__(self, point_key: Point, params: UmbralParameters) -> None:
        """
        Initializes an Umbral public key.
        """
        self.params = params

        if not isinstance(point_key, Point):
            raise TypeError("point_key can only be a Point.  Don't pass anything else.")

        self.point_key = point_key

    @classmethod
    def from_bytes(cls,
                   key_bytes: bytes,
                   params: Optional[UmbralParameters] = None,
                   decoder: Optional[Callable] = None) -> 'UmbralPublicKey':
        """
        Loads an Umbral public key from bytes.
        Optionally, if an decoder function is provided it will be used to decode
        the data before returning it as an Umbral key.
        """
        if params is None:
            params = default_params()

        if decoder:
            key_bytes = decoder(key_bytes)

        point_key = Point.from_bytes(key_bytes, params.curve)
        return cls(point_key, params)

    @classmethod
    def expected_bytes_length(cls, curve: Optional[Curve] = None,
                              is_compressed: bool = True):
        """
        Returns the size (in bytes) of an UmbralPublicKey given a curve.
        If no curve is provided, it uses the default curve.
        By default, it assumes compressed representation (is_compressed = True).
        """
        return Point.expected_bytes_length(curve=curve, is_compressed=is_compressed)

    def to_bytes(self, encoder: Callable = None, is_compressed: bool = True):
        """
        Returns an Umbral public key as bytes.
        Optionally, if an encoder function is provided it will be used to encode
        the data before returning it.
        """
        umbral_pubkey = self.point_key.to_bytes(is_compressed=is_compressed)

        if encoder:
            umbral_pubkey = encoder(umbral_pubkey)

        return umbral_pubkey

    def to_cryptography_pubkey(self) -> _EllipticCurvePublicKey:
        """
        Returns a cryptography.io EllipticCurvePublicKey from the Umbral key.
        """
        backend = default_backend()

        backend.openssl_assert(self.point_key.curve.ec_group != backend._ffi.NULL)
        backend.openssl_assert(self.point_key.ec_point != backend._ffi.NULL)

        ec_key = backend._lib.EC_KEY_new()
        backend.openssl_assert(ec_key != backend._ffi.NULL)
        ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

        set_group_result = backend._lib.EC_KEY_set_group(
            ec_key, self.point_key.curve.ec_group
        )
        backend.openssl_assert(set_group_result == 1)

        set_pubkey_result = backend._lib.EC_KEY_set_public_key(
            ec_key, self.point_key.ec_point
        )
        backend.openssl_assert(set_pubkey_result == 1)

        evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
        return _EllipticCurvePublicKey(backend, ec_key, evp_pkey)

    def __bytes__(self) -> bytes:
        """
        Returns an Umbral Public key as a bytestring.
        """
        return self.point_key.to_bytes()

    def __repr__(self):
        return "{}:{}".format(self.__class__.__name__, self.point_key.to_bytes().hex()[:15])

    def __eq__(self, other: Any) -> bool:
        if type(other) == bytes:
            is_eq = bytes(other) == bytes(self)
        elif hasattr(other, "point_key") and hasattr(other, "params"):
            is_eq = (self.point_key, self.params) == (other.point_key, other.params)
        else:
            is_eq = False
        return is_eq

    def __hash__(self) -> int:
        return int.from_bytes(self.to_bytes(), byteorder="big")


class UmbralKeyingMaterial:
    """
    This class handles keying material for Umbral, by allowing deterministic
    derivation of UmbralPrivateKeys based on labels. 
    Don't use this key material directly as a key.
    """

    def __init__(self, keying_material: Optional[bytes] = None) -> None:
        """
        Initializes an UmbralKeyingMaterial.
        """
        if keying_material:
            if len(keying_material) < 32:
                raise ValueError("UmbralKeyingMaterial must have size at least 32 bytes.")
            self.__keying_material = keying_material
        else:
            self.__keying_material = os.urandom(64)

    def derive_privkey_by_label(self,
                                label: bytes,
                                salt: Optional[bytes] = None,
                                params: Optional[UmbralParameters] = None) -> UmbralPrivateKey:
        """
        Derives an UmbralPrivateKey using a KDF from this instance of 
        UmbralKeyingMaterial, a label, and an optional salt.
        """
        params = params if params is not None else default_params()

        key_material = HKDF(
            algorithm=hashes.BLAKE2b(64),
            length=64,
            salt=salt,
            info=b"NuCypher/KeyDerivation/"+label,
            backend=default_backend()
        ).derive(self.__keying_material)

        bn_key = hash_to_curvebn(key_material, params=params)
        return UmbralPrivateKey(bn_key, params)

    @classmethod
    def from_bytes(cls,
                   key_bytes: bytes,
                   wrapping_key: Optional[bytes] = None,
                   password: Optional[bytes] = None,
                   decoder: Optional[Callable] = None,
                   **kwargs) -> 'UmbralKeyingMaterial':
        """
        Loads an UmbralKeyingMaterial from bytes.
        Optionally, allows a decoder function to be passed as a param to decode
        the data provided before converting to an Umbral key.
        Optionally, uses a wrapping key to unwrap an encrypted UmbralKeyingMaterial.
        Alternatively, if a password is provided it will derive the wrapping key
        from it.
        """
        if decoder:
            key_bytes = decoder(key_bytes)

        if any((password, wrapping_key)):
            key_bytes = unwrap_key(wrapped_key=key_bytes,
                                   wrapping_key=wrapping_key,
                                   password=password,
                                   **kwargs)

        return cls(keying_material=key_bytes)

    def to_bytes(self,
                 wrapping_key: Optional[bytes] = None,
                 password: Optional[bytes] = None,
                 encoder: Optional[Callable] = None,
                 **kwargs) -> bytes:
        """
        Returns an UmbralKeyingMaterial as bytes with optional symmetric
        encryption via nacl's Salsa20-Poly1305.
        If a password is provided instead of a wrapping key, it will use
        Scrypt for key derivation.
        Optionally, allows an encoder to be passed in as a param to encode the
        data before returning it.
        """

        key_bytes = self.__keying_material

        if any((password, wrapping_key)):
            key_bytes = wrap_key(key_to_wrap=key_bytes,
                                 wrapping_key=wrapping_key,
                                 password=password,
                                 **kwargs)

        if encoder:
            key_bytes = encoder(key_bytes)

        return key_bytes
