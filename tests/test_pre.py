import pytest

from umbral import (
    SecretKey,
    Signer,
    KeyFrag,
    CapsuleFrag,
    encrypt,
    generate_kfrags,
    decrypt_original,
    reencrypt,
    decrypt_reencrypted,
    )


def test_public_key_encryption(alices_keys):
    delegating_sk, _ = alices_keys
    delegating_pk = delegating_sk.public_key()
    plaintext = b'peace at dawn'
    capsule, ciphertext = encrypt(delegating_pk, plaintext)
    plaintext_decrypted = decrypt_original(delegating_sk, capsule, ciphertext)
    assert plaintext == plaintext_decrypted

    # Wrong secret key
    sk = SecretKey.random()
    with pytest.raises(ValueError):
        decrypt_original(sk, capsule, ciphertext)


SIMPLE_API_PARAMETERS = (
    # (num_kfrags, threshold)
    (1, 1),
    (6, 1),
    (6, 4),
    (6, 6),
    (50, 30)
)

@pytest.mark.parametrize("num_kfrags, threshold", SIMPLE_API_PARAMETERS)
def test_simple_api(num_kfrags, threshold):
    """
    This test models the main interactions between actors (i.e., Alice,
    Bob, Data Source, and Ursulas) and artifacts (i.e., public and private keys,
    ciphertexts, capsules, KFrags, CFrags, etc).

    The test covers all the main stages of data sharing:
    key generation, delegation, encryption, decryption by
    Alice, re-encryption by Ursula, and decryption by Bob.
    """

    # Key Generation (Alice)
    delegating_sk = SecretKey.random()
    delegating_pk = delegating_sk.public_key()

    signing_sk = SecretKey.random()
    signer = Signer(signing_sk)
    verifying_pk = signing_sk.public_key()

    # Key Generation (Bob)
    receiving_sk = SecretKey.random()
    receiving_pk = receiving_sk.public_key()

    # Encryption by an unnamed data source
    plaintext = b'peace at dawn'
    capsule, ciphertext = encrypt(delegating_pk, plaintext)

    # Decryption by Alice
    plaintext_decrypted = decrypt_original(delegating_sk, capsule, ciphertext)
    assert plaintext_decrypted == plaintext

    # Split Re-Encryption Key Generation (aka Delegation)
    kfrags = generate_kfrags(delegating_sk=delegating_sk,
                             receiving_pk=receiving_pk,
                             signer=signer,
                             threshold=threshold,
                             num_kfrags=num_kfrags)

    # Bob requests re-encryption to some set of M ursulas
    cfrags = [reencrypt(capsule, kfrag) for kfrag in kfrags]

    # Decryption by Bob
    plaintext_reenc = decrypt_reencrypted(receiving_sk=receiving_sk,
                                          delegating_pk=delegating_pk,
                                          capsule=capsule,
                                          verified_cfrags=cfrags[:threshold],
                                          ciphertext=ciphertext,
                                          )

    assert plaintext_reenc == plaintext


def test_reencrypt_unverified_kfrag(capsule, kfrags):
    kfrag = KeyFrag.from_bytes(bytes(kfrags[0]))
    with pytest.raises(TypeError):
        reencrypt(capsule, kfrag)


def test_decrypt_unverified_cfrag(verification_keys, bobs_keys, capsule_and_ciphertext, kfrags):
    verifying_pk, delegating_pk, receiving_pk = verification_keys
    receiving_sk, _receiving_pk = bobs_keys
    capsule, ciphertext = capsule_and_ciphertext

    cfrags = [reencrypt(capsule, kfrag) for kfrag in kfrags]
    cfrags[0] = CapsuleFrag.from_bytes(bytes(cfrags[0]))
    with pytest.raises(TypeError):
        plaintext_reenc = decrypt_reencrypted(receiving_sk=receiving_sk,
                                              delegating_pk=delegating_pk,
                                              capsule=capsule,
                                              verified_cfrags=cfrags,
                                              ciphertext=ciphertext,
                                              )


def test_wrong_num_kfrags(alices_keys, bobs_keys):
    delegating_sk, signing_sk = alices_keys
    _receiving_sk, receiving_pk = bobs_keys

    # Trying to create less kfrags than the threshold
    with pytest.raises(ValueError):
        generate_kfrags(delegating_sk=delegating_sk,
                        signer=Signer(signing_sk),
                        receiving_pk=receiving_pk,
                        threshold=3,
                        num_kfrags=2)
