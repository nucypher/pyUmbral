from typing import Tuple, Optional, Sequence

from .capsule import Capsule
from .capsule_frag import VerifiedCapsuleFrag, CapsuleFrag
from .dem import DEM
from .keys import PublicKey, SecretKey
from .key_frag import VerifiedKeyFrag, KeyFrag


def encrypt(pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    """
    Generates and encapsulates a symmetric key and uses it to encrypt the given plaintext.

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


def reencrypt(capsule: Capsule,
              kfrag: VerifiedKeyFrag,
              metadata: Optional[bytes] = None
              ) -> VerifiedCapsuleFrag:
    """
    Creates a capsule fragment using the given key fragment.
    Capsule fragments can later be used to decrypt the ciphertext.

    If `metadata` is provided, it will have to be used for verification in
    :py:meth:`CapsuleFrag.verify`.
    """
    # We could let duck typing do its work,
    # but it's better to make a common error more understandable.
    if isinstance(kfrag, KeyFrag) and not isinstance(kfrag, VerifiedKeyFrag):
        raise TypeError("KeyFrag must be verified before reencryption")

    return VerifiedCapsuleFrag(CapsuleFrag.reencrypted(capsule, kfrag.kfrag, metadata))


def decrypt_reencrypted(decrypting_sk: SecretKey,
                        delegating_pk: PublicKey,
                        capsule: Capsule,
                        verified_cfrags: Sequence[VerifiedCapsuleFrag],
                        ciphertext: bytes,
                        ) -> bytes:
    """
    Decrypts the ciphertext using the original capsule and the reencrypted capsule fragments.
    """
    # We could let duck typing do its work,
    # but it's better to make a common error more understandable.
    for cfrag in verified_cfrags:
        if isinstance(cfrag, CapsuleFrag) and not isinstance(cfrag, VerifiedCapsuleFrag):
            raise TypeError("All CapsuleFrags must be verified before decryption")

    cfrags = [vcfrag.cfrag for vcfrag in verified_cfrags]
    key_seed = capsule.open_reencrypted(decrypting_sk, delegating_pk, cfrags)
    dem = DEM(bytes(key_seed))
    return dem.decrypt(ciphertext, authenticated_data=bytes(capsule))

