.. role:: bash(code)
   :language: bash

=========
pyUmbral
=========

.. image:: https://travis-ci.org/nucypher/pyUmbral.svg?branch=master
    :target: https://travis-ci.org/nucypher/pyUmbral

pyUmbral is a python implementation of Umbral using OpenSSL and Cryptography.io,
enabling users to perform *split-key proxy-rencryption* and public key encryption
in an understandable and usable manner.

**Public Key Encryption**

.. code-block:: python

    from umbral import umbral, keys

    # Generate umbral keys for Alice.
    alices_private_key = keys.UmbralPrivateKey.gen_key()
    alices_public_key = private_key.get_pubkey()

    # Encrypt data with Alice's public key.
    plaintext = b'Proxy Re-encryption is cool!'
    ciphertext, capsule = umbral.encrypt(alices_public_key, plaintext)

    # Decrypt data with Alice's private key.
    cleartext = umbral.decrypt(capsule, alices_private_key,
                               ciphertext, alices_public_key)

**Generate Split Re-Encryption Keys**

.. code-block:: python

    # Generate umbral keys for Bob.
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = private_key.get_pubkey()

    # Generate split re-encryption keys with "M of N".
    kfrags, _ = umbral.split_rekey(alices_private_key, bobs_public_key, 10, 20)


**Proxy Re-encryption**

.. code-block:: python

  # Ursula exchanges key fragments with Bob.
  # Bob attaches the cfrags to the capsule.
  for kfrag in kfrags:
      cfrag = umbral.reencrypt(kfrag, capsule)
      capsule.attach_cfrag(cfrag)

  # Bob activates and opens the capsule.
  cleartext = umbral.decrypt(capsule, bobs_private_key,
                             ciphertext, alices_public_key)


Features
==========
- Proxy Re-encryption
- Threshold Proxy Re-encryption Key Splitting
- Data and Key Encapsulation
- Public Key Encryption & Decryption


Quick Installation
==================

The NuCypher team uses pipenv for managing pyUmbral's dependencies.
The recommended installation procedure is as follows:

.. code-block:: bash

    $ sudo pip3 install pipenv
    $ pipenv install

Post-installation, you can activate the project virtual enviorment
in your current terminal session by running :bash:`pipenv shell`.

For more information on pipenv, find the official documentation here: https://docs.pipenv.org/.


Technical Documentation
========================
  "Umbral: A Threshold Proxy Re-Encryption Scheme"
  by David Nuñez

Technical documentation and cryptographic specifications
are availible on GitHub https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf


Support & Contribute
=====================

- Issue Tracker: https://github.com/nucypher/pyUmbral/issues
- Source Code: https://github.com/nucypher/pyUmbral
