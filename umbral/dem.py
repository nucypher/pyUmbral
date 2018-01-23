from umbral.umbral import UmbralParameters
from umbral.keys import UmbralPrivateKey, UmbralPublicKey


class UmbralDEM(object):
    def __init__(self, params: UmbralParameters, recp_pub_key: UmbralPublicKey):
        self.params = params
        self.recp_pub_key = recp_pub_key

    def encrypt(self):
        pass

    def decrypt(self):
        pass

    def decrypt_reencrypted(self):
        pass

    def split_rekey(self):
        pass

    def reencrypt(self):
        pass

    def reconstruct(self):
        pass
