from typing import Tuple, Optional, Sequence

from .capsule import Capsule
from .capsule_frag import CapsuleFrag
from .dem import DEM
from .keys import PublicKey, SecretKey
from .key_frag import KeyFrag


def encrypt(pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    """
    Performs an encryption using the UmbralDEM object and encapsulates a key
    for the sender using the public key provided.

    Returns the KEM Capsule and the ciphertext.
    """
    capsule, key_seed = Capsule.from_public_key(pk)
    dem = DEM(bytes(key_seed))
    ciphertext = dem.encrypt(plaintext, authenticated_data=bytes(capsule))
    return capsule, ciphertext


def decrypt_original(sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes:
    """
    Opens the capsule using the original (Alice's) key used for encryption and gets what's inside.
    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    key_seed = capsule.open_original(sk)
    dem = DEM(bytes(key_seed))
    return dem.decrypt(ciphertext, authenticated_data=bytes(capsule))


def reencrypt(capsule: Capsule, kfrag: KeyFrag, metadata: Optional[bytes] = None) -> CapsuleFrag:
    return CapsuleFrag.reencrypted(capsule, kfrag, metadata)


def decrypt_reencrypted(decrypting_sk: SecretKey,
                        delegating_pk: PublicKey,
                        capsule: Capsule,
                        cfrags: Sequence[CapsuleFrag],
                        ciphertext: bytes,
                        ) -> bytes:

    key_seed = capsule.open_reencrypted(decrypting_sk, delegating_pk, cfrags)
    # TODO: add salt and info here?
    dem = DEM(bytes(key_seed))
    return dem.decrypt(ciphertext, authenticated_data=bytes(capsule))

