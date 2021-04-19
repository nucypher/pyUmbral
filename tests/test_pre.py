import pytest

from umbral import (
    SecretKey,
    PublicKey,
    Signer,
    GenericError,
    encrypt,
    generate_kfrags,
    decrypt_original,
    reencrypt,
    decrypt_reencrypted,
    )


def test_public_key_encryption(alices_keys):
    delegating_sk, _ = alices_keys
    delegating_pk = PublicKey.from_secret_key(delegating_sk)
    plaintext = b'peace at dawn'
    capsule, ciphertext = encrypt(delegating_pk, plaintext)
    plaintext_decrypted = decrypt_original(delegating_sk, capsule, ciphertext)
    assert plaintext == plaintext_decrypted

    # Wrong secret key
    sk = SecretKey.random()
    with pytest.raises(GenericError):
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
    delegating_pk = PublicKey.from_secret_key(delegating_sk)

    signing_sk = SecretKey.random()
    signer = Signer(signing_sk)
    verifying_pk = PublicKey.from_secret_key(signing_sk)

    # Key Generation (Bob)
    receiving_sk = SecretKey.random()
    receiving_pk = PublicKey.from_secret_key(receiving_sk)

    # Encryption by an unnamed data source
    plaintext = b'peace at dawn'
    capsule, ciphertext = encrypt(delegating_pk, plaintext)

    # Decryption by Alice
    plaintext_decrypted = decrypt_original(delegating_sk, capsule, ciphertext)
    assert plaintext_decrypted == plaintext

    # Split Re-Encryption Key Generation (aka Delegation)
    kfrags = generate_kfrags(delegating_sk=delegating_sk,
                             receiving_pk=receiving_pk,
                             signer=signer,
                             threshold=threshold,
                             num_kfrags=num_kfrags)

    # Bob requests re-encryption to some set of M ursulas
    cfrags = list()
    for kfrag in kfrags[:threshold]:
        # Ursula checks that the received kfrag is valid
        assert kfrag.verify(verifying_pk=verifying_pk,
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk)

        # Re-encryption by an Ursula
        cfrag = reencrypt(capsule, kfrag)

        # Bob collects the result
        cfrags.append(cfrag)

    # Bob checks that the received cfrags are valid
    assert all(cfrag.verify(capsule=capsule,
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk,
                            verifying_pk=verifying_pk) for cfrag in cfrags)

    # Decryption by Bob
    plaintext_reenc = decrypt_reencrypted(receiving_sk,
                                          delegating_pk,
                                          capsule,
                                          cfrags[:threshold],
                                          ciphertext,
                                          )

    assert plaintext_reenc == plaintext
