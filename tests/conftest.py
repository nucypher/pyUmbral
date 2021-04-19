import pytest

from umbral import SecretKey, PublicKey, Signer, generate_kfrags, encrypt


@pytest.fixture
def alices_keys():
    delegating_sk = SecretKey.random()
    signing_sk = SecretKey.random()
    return delegating_sk, signing_sk


@pytest.fixture
def bobs_keys():
    sk = SecretKey.random()
    pk = PublicKey.from_secret_key(sk)
    return sk, pk


@pytest.fixture
def kfrags(alices_keys, bobs_keys):
    delegating_sk, signing_sk = alices_keys
    receiving_sk, receiving_pk = bobs_keys
    yield generate_kfrags(delegating_sk=delegating_sk,
                          signer=Signer(signing_sk),
                          receiving_pk=receiving_pk,
                          threshold=6, num_kfrags=10)


@pytest.fixture(scope='session')
def message():
    message = (b"dnunez [9:30 AM]"
               b"@Tux we had this super fruitful discussion last night with @jMyles @michwill @KPrasch"
               b"to sum up: the symmetric ciphertext is now called the 'Chimney'."
               b"the chimney of the capsule, of course"
               b"tux [9:32 AM]"
               b"wat")
    return message


@pytest.fixture
def capsule_and_ciphertext(alices_keys, message):
    delegating_sk, _signing_sk = alices_keys
    capsule, ciphertext = encrypt(PublicKey.from_secret_key(delegating_sk), message)
    return capsule, ciphertext


@pytest.fixture
def capsule(capsule_and_ciphertext):
    capsule, ciphertext = capsule_and_ciphertext
    return capsule
