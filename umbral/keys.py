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
from typing import Callable, Optional, Union, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePrivateKey, _EllipticCurvePublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from nacl.secret import SecretBox

from umbral import openssl
from umbral.config import default_params
from umbral.curvebn import CurveBN
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.curve import Curve


class UmbralPrivateKey(object):
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
                   params: Optional[UmbralParameters] = None,
                   password: Optional[bytes] = None,
                   _scrypt_cost: int = 20,
                   decoder: Optional[Callable] = None) -> 'UmbralPrivateKey':
        """
        Loads an Umbral private key from bytes.
        Optionally, allows a decoder function to be passed as a param to decode
        the data provided before converting to an Umbral key.
        Optionally, if a password is provided it will decrypt the key using
        nacl's Salsa20-Poly1305 and Scrypt key derivation.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. Unless you changed this when you called `to_bytes`, you should
        not change it here. It is NOT recommended to change the `_scrypt_cost`
        value unless you know what you're doing.
        """
        if params is None:
            params = default_params()

        if decoder:
            key_bytes = decoder(key_bytes)

        if password:
            salt = key_bytes[-16:]
            key_bytes = key_bytes[:-16]

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            key_bytes = SecretBox(key).decrypt(key_bytes)

        bn_key = CurveBN.from_bytes(key_bytes, params.curve)
        return cls(bn_key, params)

    def to_bytes(self,
                 password: Optional[bytes] = None,
                 _scrypt_cost: int = 20,
                 encoder: Optional[Callable] = None) -> bytes:
        """
        Returns an Umbral private key as bytes optional symmetric encryption
        via nacl's Salsa20-Poly1305 and Scrypt key derivation. If a password
        is provided, the user must encode it to bytes.
        Optionally, allows an encoder to be passed in as a param to encode the
        data before returning it.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. It is NOT recommended to change the `_scrypt_cost` value unless
        you know what you are doing.
        """
        umbral_privkey = self.bn_key.to_bytes()

        if password:
            salt = os.urandom(16)

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            umbral_privkey = SecretBox(key).encrypt(umbral_privkey)
            umbral_privkey += salt

        if encoder:
            umbral_privkey = encoder(umbral_privkey)

        return umbral_privkey

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


class UmbralPublicKey(object):
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


class UmbralKeyingMaterial(object):
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
            self.keying_material = keying_material
        else:
            self.keying_material = os.urandom(64)

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
        ).derive(self.keying_material)

        bn_key = CurveBN.hash(key_material, params=params)
        return UmbralPrivateKey(bn_key, params)

    @classmethod
    def from_bytes(cls,
                   key_bytes: bytes,
                   password: Optional[bytes] = None,
                   _scrypt_cost: int = 20) -> 'UmbralKeyingMaterial':
        """
        Loads an UmbralKeyingMaterial from a urlsafe base64 encoded string.
        Optionally, if a password is provided it will decrypt the key using
        nacl's Salsa20-Poly1305 and Scrypt key derivation.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. Unless you changed this when you called `to_bytes`, you should
        not change it here. It is NOT recommended to change the `_scrypt_cost`
        value unless you know what you're doing.
        """

        if password:
            salt = key_bytes[-16:]
            key_bytes = key_bytes[:-16]

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            key_bytes = SecretBox(key).decrypt(key_bytes)

        return cls(key_bytes)

    def to_bytes(self, password: Optional[bytes] = None, _scrypt_cost: int = 20) -> bytes:
        """
        Returns an UmbralKeyingMaterial as a urlsafe base64 encoded string with
        optional symmetric encryption via nacl's Salsa20-Poly1305 and Scrypt
        key derivation. If a password is provided, the user must encode it to
        bytes.

        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. It is NOT recommended to change the `_scrypt_cost` value unless
        you know what you are doing.
        """

        umbral_keying_material = self.keying_material

        if password:
            salt = os.urandom(16)

            key = Scrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2**_scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)

            umbral_keying_material = SecretBox(key).encrypt(umbral_keying_material)
            umbral_keying_material += salt

        encoded_key = umbral_keying_material
        return encoded_key
