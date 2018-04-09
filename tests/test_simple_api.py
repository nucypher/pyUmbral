import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import pre, keys
from umbral.config import default_curve
from umbral.params import UmbralParameters
from .conftest import parameters

secp_curves = [
    ec.SECP384R1,
    ec.SECP192R1
]


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""

    params = UmbralParameters(curve=curve)

    priv_key_alice = keys.UmbralPrivateKey.gen_key(params=params)
    pub_key_alice = priv_key_alice.get_pubkey()

    priv_key_bob = keys.UmbralPrivateKey.gen_key(params=params)
    pub_key_bob = priv_key_bob.get_pubkey()

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice, plain_data, params=params)

    cleartext = pre.decrypt(ciphertext, capsule, priv_key_alice, params=params)
    assert cleartext == plain_data

    kfrags = pre.split_rekey(priv_key_alice, pub_key_bob, M, N, params=params)
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule, params=params)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, priv_key_bob, pub_key_alice, params=params)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", secp_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    test_simple_api(N, M, curve)


def test_public_key_encryption(alices_keys):
    priv_key_alice, pub_key_alice = alices_keys
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(pub_key_alice, plain_data)
    cleartext = pre.decrypt(ciphertext, capsule, priv_key_alice)
    assert cleartext == plain_data
