import pytest

try:
    import umbral_pre as umbral_rs
except ImportError:
    umbral_rs = None

import umbral as umbral_py


def pytest_generate_tests(metafunc):
    if 'implementations' in metafunc.fixturenames:
        implementations = [(umbral_py, umbral_py)]
        ids = ['python -> python']
        if umbral_rs is not None:
            implementations.extend([(umbral_py, umbral_rs), (umbral_rs, umbral_py)])
            ids.extend(['python -> rust', 'rust -> python'])

        metafunc.parametrize('implementations', implementations, ids=ids)


def _create_keypair(umbral):
    sk = umbral.SecretKey.random()
    pk = umbral.PublicKey.from_secret_key(sk)
    return bytes(sk), bytes(pk)


def _restore_keys(umbral, sk_bytes, pk_bytes):
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    pk_from_sk = umbral.PublicKey.from_secret_key(sk)
    pk_from_bytes = umbral.PublicKey.from_bytes(pk_bytes)
    assert pk_from_sk == pk_from_bytes


def test_keys(implementations):
    umbral1, umbral2 = implementations

    # On client 1
    sk_bytes, pk_bytes = _create_keypair(umbral1)

    # On client 2
    _restore_keys(umbral2, sk_bytes, pk_bytes)


def _create_sk_factory_and_sk(umbral, label):
    skf = umbral.SecretKeyFactory.random()
    sk = skf.secret_key_by_label(label)
    return bytes(skf), bytes(sk)


def _check_sk_is_same(umbral, label, skf_bytes, sk_bytes):
    skf = umbral.SecretKeyFactory.from_bytes(skf_bytes)
    sk_restored = umbral.SecretKey.from_bytes(sk_bytes)
    sk_generated = skf.secret_key_by_label(label)
    assert sk_restored == sk_generated


def test_secret_key_factory(implementations):
    umbral1, umbral2 = implementations
    label = b'label'

    skf_bytes, sk_bytes = _create_sk_factory_and_sk(umbral1, label)
    _check_sk_is_same(umbral2, label, skf_bytes, sk_bytes)


def _encrypt(umbral, plaintext, pk_bytes):
    pk = umbral.PublicKey.from_bytes(pk_bytes)
    capsule, ciphertext = umbral.encrypt(pk, plaintext)
    return bytes(capsule), ciphertext


def _decrypt_original(umbral, sk_bytes, capsule_bytes, ciphertext):
    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    return umbral.decrypt_original(sk, capsule, ciphertext)


def test_encrypt_decrypt(implementations):

    umbral1, umbral2 = implementations
    plaintext = b'peace at dawn'

    # On client 1
    sk_bytes, pk_bytes = _create_keypair(umbral1)

    # On client 2
    capsule_bytes, ciphertext = _encrypt(umbral2, plaintext, pk_bytes)

    # On client 1
    plaintext_decrypted = _decrypt_original(umbral1, sk_bytes, capsule_bytes, ciphertext)

    assert plaintext_decrypted == plaintext


def _generate_kfrags(umbral, delegating_sk_bytes, receiving_pk_bytes,
                     signing_sk_bytes, threshold, num_kfrags):

    delegating_sk = umbral.SecretKey.from_bytes(delegating_sk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    signing_sk = umbral.SecretKey.from_bytes(signing_sk_bytes)

    kfrags = umbral.generate_kfrags(delegating_sk=delegating_sk,
                                    receiving_pk=receiving_pk,
                                    signer=umbral.Signer(signing_sk),
                                    threshold=threshold,
                                    num_kfrags=num_kfrags,
                                    sign_delegating_key=True,
                                    sign_receiving_key=True,
                                    )

    return [bytes(kfrag) for kfrag in kfrags]


def _verify_kfrags(umbral, kfrags_bytes, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes):
    kfrags = [umbral.KeyFrag.from_bytes(kfrag_bytes) for kfrag_bytes in kfrags_bytes]
    verifying_pk = umbral.PublicKey.from_bytes(verifying_pk_bytes)
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    return [kfrag.verify(verifying_pk=verifying_pk,
                         delegating_pk=delegating_pk,
                         receiving_pk=receiving_pk) for kfrag in kfrags]


def test_kfrags(implementations):

    umbral1, umbral2 = implementations

    threshold = 2
    num_kfrags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, verifying_pk_bytes = _create_keypair(umbral1)
    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_kfrags)

    # On client 2

    _verify_kfrags(umbral2, kfrags_bytes, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes)


def _reencrypt(umbral, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes,
               capsule_bytes, kfrags_bytes, threshold):
    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    verified_kfrags = _verify_kfrags(umbral, kfrags_bytes,
                                     verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes)
    cfrags = [umbral.reencrypt(capsule, kfrag) for kfrag in verified_kfrags[:threshold]]
    return [bytes(cfrag) for cfrag in cfrags]


def _decrypt_reencrypted(umbral, receiving_sk_bytes, delegating_pk_bytes, verifying_pk_bytes,
                         capsule_bytes, cfrags_bytes, ciphertext):

    receiving_sk = umbral.SecretKey.from_bytes(receiving_sk_bytes)
    receiving_pk = umbral.PublicKey.from_secret_key(receiving_sk)
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    verifying_pk = umbral.PublicKey.from_bytes(verifying_pk_bytes)

    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    cfrags = [umbral.CapsuleFrag.from_bytes(cfrag_bytes) for cfrag_bytes in cfrags_bytes]

    verified_cfrags = [cfrag.verify(capsule,
                                    verifying_pk=verifying_pk,
                                    delegating_pk=delegating_pk,
                                    receiving_pk=receiving_pk,
                                    )
                       for cfrag in cfrags]

    # Decryption by Bob
    plaintext = umbral.decrypt_reencrypted(decrypting_sk=receiving_sk,
                                           delegating_pk=delegating_pk,
                                           capsule=capsule,
                                           verified_cfrags=verified_cfrags,
                                           ciphertext=ciphertext,
                                           )

    return plaintext


def test_reencrypt(implementations):

    umbral1, umbral2 = implementations

    threshold = 2
    num_kfrags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, verifying_pk_bytes = _create_keypair(umbral1)

    capsule_bytes, ciphertext = _encrypt(umbral1, plaintext, delegating_pk_bytes)

    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_kfrags)

    # On client 2

    cfrags_bytes = _reencrypt(umbral2, verifying_pk_bytes, delegating_pk_bytes, receiving_pk_bytes,
                              capsule_bytes, kfrags_bytes, threshold)

    # On client 1

    plaintext_reencrypted = _decrypt_reencrypted(umbral1,
                                                 receiving_sk_bytes, delegating_pk_bytes, verifying_pk_bytes,
                                                 capsule_bytes, cfrags_bytes, ciphertext)

    assert plaintext_reencrypted == plaintext


def _sign_message(umbral, sk_bytes, message):
    sk = umbral.SecretKey.from_bytes(sk_bytes)
    signer = umbral.Signer(sk)
    assert signer.verifying_key() == umbral.PublicKey.from_secret_key(sk)
    return bytes(signer.sign(message))


def _verify_message(umbral, pk_bytes, signature_bytes, message):
    pk = umbral.PublicKey.from_bytes(pk_bytes)
    signature = umbral.Signature.from_bytes(signature_bytes)
    return signature.verify(pk, message)


def test_signer(implementations):

    umbral1, umbral2 = implementations

    message = b'peace at dawn'

    sk_bytes, pk_bytes = _create_keypair(umbral1)

    signature1_bytes = _sign_message(umbral1, sk_bytes, message)
    signature2_bytes = _sign_message(umbral2, sk_bytes, message)

    # Signatures are random, so we can't compare them.
    # Cross-verify instead

    assert _verify_message(umbral1, pk_bytes, signature2_bytes, message)
    assert _verify_message(umbral2, pk_bytes, signature1_bytes, message)
