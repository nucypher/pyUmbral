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
                     signing_sk_bytes, threshold, num_frags):

    delegating_sk = umbral.SecretKey.from_bytes(delegating_sk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    signing_sk = umbral.SecretKey.from_bytes(signing_sk_bytes)

    kfrags = umbral.generate_kfrags(delegating_sk,
                                    receiving_pk,
                                    signing_sk,
                                    threshold,
                                    num_frags,
                                    True,
                                    True,
                                    )

    return [bytes(kfrag) for kfrag in kfrags]


def _verify_kfrags(umbral, kfrags_bytes, signing_pk_bytes, delegating_pk_bytes, receiving_pk_bytes):
    kfrags = [umbral.KeyFrag.from_bytes(kfrag_bytes) for kfrag_bytes in kfrags_bytes]
    signing_pk = umbral.PublicKey.from_bytes(signing_pk_bytes)
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    receiving_pk = umbral.PublicKey.from_bytes(receiving_pk_bytes)
    assert all(kfrag.verify(signing_pk, delegating_pk, receiving_pk) for kfrag in kfrags)


def test_kfrags(implementations):

    umbral1, umbral2 = implementations

    threshold = 2
    num_frags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, signing_pk_bytes = _create_keypair(umbral1)
    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_frags)

    # On client 2

    _verify_kfrags(umbral2, kfrags_bytes, signing_pk_bytes, delegating_pk_bytes, receiving_pk_bytes)


def _reencrypt(umbral, capsule_bytes, kfrags_bytes, threshold, metadata):
    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    kfrags = [umbral.KeyFrag.from_bytes(kfrag_bytes) for kfrag_bytes in kfrags_bytes]
    cfrags = [umbral.reencrypt(capsule, kfrag, metadata=metadata) for kfrag in kfrags[:threshold]]
    return [bytes(cfrag) for cfrag in cfrags]


def _decrypt_reencrypted(umbral, receiving_sk_bytes, delegating_pk_bytes, signing_pk_bytes,
                         capsule_bytes, cfrags_bytes, ciphertext, metadata):

    receiving_sk = umbral.SecretKey.from_bytes(receiving_sk_bytes)
    receiving_pk = umbral.PublicKey.from_secret_key(receiving_sk)
    delegating_pk = umbral.PublicKey.from_bytes(delegating_pk_bytes)
    signing_pk = umbral.PublicKey.from_bytes(signing_pk_bytes)

    capsule = umbral.Capsule.from_bytes(bytes(capsule_bytes))
    cfrags = [umbral.CapsuleFrag.from_bytes(cfrag_bytes) for cfrag_bytes in cfrags_bytes]

    assert all(cfrag.verify(capsule, delegating_pk, receiving_pk, signing_pk, metadata=metadata)
               for cfrag in cfrags)

    # Decryption by Bob
    plaintext = umbral.decrypt_reencrypted(receiving_sk,
                                           delegating_pk,
                                           capsule,
                                           cfrags,
                                           ciphertext,
                                           )

    return plaintext


def test_reencrypt(implementations):

    umbral1, umbral2 = implementations

    metadata = b'metadata'
    threshold = 2
    num_frags = 3
    plaintext = b'peace at dawn'

    # On client 1

    receiving_sk_bytes, receiving_pk_bytes = _create_keypair(umbral1)
    delegating_sk_bytes, delegating_pk_bytes = _create_keypair(umbral1)
    signing_sk_bytes, signing_pk_bytes = _create_keypair(umbral1)

    capsule_bytes, ciphertext = _encrypt(umbral1, plaintext, delegating_pk_bytes)

    kfrags_bytes = _generate_kfrags(umbral1, delegating_sk_bytes, receiving_pk_bytes,
                                    signing_sk_bytes, threshold, num_frags)

    # On client 2

    cfrags_bytes = _reencrypt(umbral2, capsule_bytes, kfrags_bytes, threshold, metadata)

    # On client 1

    plaintext_reencrypted = _decrypt_reencrypted(umbral1,
                                                 receiving_sk_bytes, delegating_pk_bytes, signing_pk_bytes,
                                                 capsule_bytes, cfrags_bytes, ciphertext, metadata)

    assert plaintext_reencrypted == plaintext
