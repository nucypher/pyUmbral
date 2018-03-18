.. role:: bash(code)
   :language: bash

=========
pyUmbral
=========

.. image:: https://travis-ci.org/nucypher/pyUmbral.svg?branch=master
    :target: https://travis-ci.org/nucypher/pyUmbral

pyUmbral is a python implementation of David Nuñez's threshold proxy re-encryption scheme: Umbral_.
Implemented with OpenSSL_ and Cryptography.io_, pyUmbral is a referential and open-source cryptography library
extending the traditional cryptological narrative of "Alice and Bob" by introducing a new actor,
*Ursula*, who has the ability to take secrets encrypted for Alice and *re-encrypt* them for Bob.

.. _Umbral: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
.. _Cryptography.io: https://cryptography.io/en/latest/
.. _OpenSSL: https://www.openssl.org/


**Encryption**

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

**Fragmentation**

.. code-block:: python

    # Generate umbral keys for Bob.
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = private_key.get_pubkey()

    # Alice generates split re-encryption keys for Bob with "M of N".
    kfrags = umbral.split_rekey(alices_private_key, bobs_public_key, 10, 20)


**Re-encryption**

.. code-block:: python

  # Ursula re-encrypts the capsule to obtain a cfrag.
  # Bob attaches the cfrags to the capsule.
  for kfrag in kfrags:
      cfrag = umbral.reencrypt(kfrag, capsule)
      capsule.attach_cfrag(cfrag)

  # Bob activates and opens the capsule.
  cleartext = umbral.decrypt(capsule, bobs_private_key,
                             ciphertext, alices_public_key)


Features
==========
- Proxy Re-encryption Toolkit
- Re-encryption Key Fragmentation
- Elliptic Curve Arithmetic


Quick Installation
==================

The NuCypher team uses pipenv for managing pyUmbral's dependencies.
The recommended installation procedure is as follows:

.. code-block:: bash

    $ sudo pip3 install pipenv
    $ pipenv install

Post-installation, you can activate the project virtual environment
in your current terminal session by running :bash:`pipenv shell`.

For more information on pipenv, find the official documentation here: https://docs.pipenv.org/.


Academic Whitepaper
====================

The Umbral scheme academic whitepaper and cryptographic specifications
are available on GitHub_.

  "Umbral: A Threshold Proxy Re-Encryption Scheme"
  *by David Nuñez*
  https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

.. _GitHub: https://github.com/nucypher/umbral-doc/


Support & Contribute
=====================

- Issue Tracker: https://github.com/nucypher/pyUmbral/issues
- Source Code: https://github.com/nucypher/pyUmbral
