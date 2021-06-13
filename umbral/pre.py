from typing import Tuple, Optional, Sequence, List

from .capsule import Capsule
from .capsule_frag import VerifiedCapsuleFrag, CapsuleFrag
from .dem import DEM
from .keys import PublicKey, SecretKey
from .key_frag import VerifiedKeyFrag, KeyFrag, KeyFragBase
from .signing import Signer


def encrypt(delegating_pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    """
    Generates and encapsulates a symmetric key and uses it to encrypt the given plaintext.

    Returns the KEM Capsule and the ciphertext.
    """
    capsule, key_seed = Capsule.from_public_key(delegating_pk)
    dem = DEM(bytes(key_seed))
    ciphertext = dem.encrypt(plaintext, authenticated_data=bytes(capsule))
    return capsule, ciphertext


def decrypt_original(delegating_sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes:
    """
    Opens the capsule using the delegator's key used for encryption and gets what's inside.
    We hope that's a symmetric key, which we use to decrypt the ciphertext
    and return the resulting cleartext.
    """
    key_seed = capsule.open_original(delegating_sk)
    dem = DEM(bytes(key_seed))
    return dem.decrypt(ciphertext, authenticated_data=bytes(capsule))


def generate_kfrags(delegating_sk: SecretKey,
                    receiving_pk: PublicKey,
                    signer: Signer,
                    threshold: int,
                    num_kfrags: int,
                    sign_delegating_key: bool = True,
                    sign_receiving_key: bool = True,
                    ) -> List[VerifiedKeyFrag]:
    """
    Generates ``num_kfrags`` key fragments to pass to proxies for re-encryption.
    At least ``threshold`` of them will be needed for decryption.
    If ``sign_delegating_key`` or ``sign_receiving_key`` are ``True``,
    the corresponding keys will have to be provided to :py:meth:`KeyFrag.verify`.
    """

    base = KeyFragBase(delegating_sk, receiving_pk, signer, threshold)

    # Technically we could allow it, but what would be the use of these kfrags?
    if num_kfrags < threshold:
        raise ValueError(f"Creating less kfrags ({num_kfrags}) "
                         f"than threshold ({threshold}) makes them useless")

    kfrags = [KeyFrag.from_base(base, sign_delegating_key, sign_receiving_key)
              for _ in range(num_kfrags)]

    # Make them verified - we know they're good.
    return [VerifiedKeyFrag(kfrag) for kfrag in kfrags]


def reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
    """
    Creates a capsule fragment using the given key fragment.
    Capsule fragments can later be used to decrypt the ciphertext.
    """
    # We could let duck typing do its work,
    # but it's better to make a common error more understandable.
    if isinstance(kfrag, KeyFrag) and not isinstance(kfrag, VerifiedKeyFrag):
        raise TypeError("KeyFrag must be verified before reencryption")

    return VerifiedCapsuleFrag(CapsuleFrag.reencrypted(capsule, kfrag.kfrag))


def decrypt_reencrypted(receiving_sk: SecretKey,
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
    key_seed = capsule.open_reencrypted(receiving_sk, delegating_pk, cfrags)
    dem = DEM(bytes(key_seed))
    return dem.decrypt(ciphertext, authenticated_data=bytes(capsule))
