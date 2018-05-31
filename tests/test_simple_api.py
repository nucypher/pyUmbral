import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from umbral import pre, keys
from umbral.config import default_curve
from umbral.params import UmbralParameters
from umbral.signing import Signer
from .conftest import parameters

secp_curves = [
    ec.SECP384R1,
    ec.SECP192R1
]


@pytest.mark.parametrize("N, M", parameters)
def test_simple_api(N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""

    params = UmbralParameters(curve=curve)

    delegating_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    delegating_pubkey = delegating_privkey.get_pubkey()

    signing_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    signing_pubkey = signing_privkey.get_pubkey()
    signer = Signer(signing_privkey)

    receiving_privkey = keys.UmbralPrivateKey.gen_key(params=params)
    receiving_pubkey = receiving_privkey.get_pubkey()

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_pubkey, plain_data, params=params)

    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey, params=params)
    assert cleartext == plain_data

    capsule.set_correctness_keys(delegating=delegating_pubkey,
                                 receiving=receiving_pubkey,
                                 verifying=signing_pubkey)

    kfrags = pre.split_rekey(delegating_privkey, signer, receiving_pubkey, M, N, params=params)

    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule, params=params)
        capsule.attach_cfrag(cfrag)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, receiving_privkey,
                                  delegating_pubkey, signing_pubkey,
                                  params=params)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", secp_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    test_simple_api(N, M, curve)


def test_public_key_encryption(alices_keys):
    delegating_privkey, _ = alices_keys
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data)
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data
