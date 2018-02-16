pyUmbral
========
.. image:: https://travis-ci.org/nucypher/pyUmbral.svg?branch=master
    :target: https://travis-ci.org/nucypher/pyUmbral

pyUmbral is a 100% python implementation of Umbral using OpenSSL and Cryptography.io

Public key encryption with pyUmbral is simple and usable:


    from umbral import umbral, keys

    # Generate a key pair
    private_key = keys.UmbralPrivateKey.gen_key()
    public_key = private_key.get_pubkey()

    # Encrypt data
    plaintext = b'Proxy Re-encryption is cool!'
    alice_ciphertext, capsule = umbral.encrypt(public_key, plaintext)

    # Decrypt data
    cleartext = umbral.decrypt(capsule, private_key, ciphertext, public_key)


Features
--------

- Asymmetric key pair generation
- Public Key Encryption
- Key Encapsulation 
- Re-encryption


Installation
------------

The NuCypher team uses pipenv for managing pyUmbral's dependencies.
The recommended installation procedure is as follows:

    sudo pip3 install pipenv
    pipenv install

Post-installation, you can activate the project virtual enviorment
in your current terminal session by running `pipenv shell`.

For more information on pipenv, find the official documentation here: https://docs.pipenv.org/. 

Support & Contribute
----------

- Issue Tracker: github.com/nucypher/pyUmbral/issues
- Source Code: github.com/nucypher/pyUmbral