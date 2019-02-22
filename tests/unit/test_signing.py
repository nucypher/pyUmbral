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

import pytest
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from umbral.keys import UmbralPrivateKey
from umbral.signing import Signer, Signature, DEFAULT_HASH_ALGORITHM


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_sign_and_verify(execution_number):
    privkey = UmbralPrivateKey.gen_key()
    pubkey = privkey.get_pubkey()
    signer = Signer(private_key=privkey)
    message = b"peace at dawn"
    signature = signer(message=message)

    # Basic signature verification
    assert signature.verify(message, pubkey)
    assert not signature.verify(b"another message", pubkey)
    another_pubkey = UmbralPrivateKey.gen_key().pubkey
    assert not signature.verify(message, another_pubkey)

    # Signature serialization
    sig_bytes = bytes(signature)
    assert len(sig_bytes) == Signature.expected_bytes_length()
    restored_signature = Signature.from_bytes(sig_bytes)
    assert restored_signature == signature
    assert restored_signature.verify(message, pubkey)


@pytest.mark.parametrize('execution_number', range(20))  # Run this test 20 times.
def test_prehashed_message(execution_number):
    privkey = UmbralPrivateKey.gen_key()
    pubkey = privkey.get_pubkey()
    signer = Signer(private_key=privkey)

    message = b"peace at dawn"
    hash_function = hashes.Hash(DEFAULT_HASH_ALGORITHM(), backend=backend)
    hash_function.update(message)
    prehashed_message = hash_function.finalize()

    signature = signer(message=prehashed_message, is_prehashed=True)

    assert signature.verify(message=prehashed_message,
                            verifying_key=pubkey,
                            is_prehashed=True)
