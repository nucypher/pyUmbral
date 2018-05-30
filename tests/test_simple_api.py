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
def test_simple_api(alices_keys, N, M, curve=default_curve()):
    """Manually injects umbralparameters for multi-curve testing."""

    params = UmbralParameters(curve=curve)

    delegating_privkey, signing_privkey = alices_keys
    decrypting_key = keys.UmbralPrivateKey.gen_key(params=params)
    signer = Signer(signing_privkey)

    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data, params=params)

    capsule.set_keys(delegating=delegating_privkey.get_pubkey(),
                     encrypting=decrypting_key.get_pubkey(),
                     verifying=signing_privkey.get_pubkey())

    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey, params=params)
    assert cleartext == plain_data

    kfrags = pre.split_rekey(delegating_privkey, signer, decrypting_key.get_pubkey(), M, N, params=params)
    for kfrag in kfrags:
        cfrag = pre.reencrypt(kfrag, capsule, params=params)
        capsule.attach_cfrag(cfrag, params=params)

    reenc_cleartext = pre.decrypt(ciphertext, capsule, decrypting_key,
                                  delegating_privkey.get_pubkey(), signing_privkey.get_pubkey(),
                                  params=params)
    assert reenc_cleartext == plain_data


@pytest.mark.parametrize("curve", secp_curves)
@pytest.mark.parametrize("N, M", parameters)
def test_simple_api_on_multiple_curves(N, M, curve):
    params = UmbralParameters(curve=curve)
    alices_keys = keys.UmbralPrivateKey.gen_key(params=params), keys.UmbralPrivateKey.gen_key(params=params)
    test_simple_api(alices_keys, N, M, curve)


def test_public_key_encryption(alices_keys):
    delegating_privkey, _ = alices_keys
    plain_data = b'peace at dawn'
    ciphertext, capsule = pre.encrypt(delegating_privkey.get_pubkey(), plain_data)
    cleartext = pre.decrypt(ciphertext, capsule, delegating_privkey)
    assert cleartext == plain_data
