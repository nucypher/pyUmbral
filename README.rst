.. role:: bash(code)
   :language: bash

=========
pyUmbral
=========

.. image:: https://travis-ci.org/nucypher/pyUmbral.svg?branch=master
    :target: https://travis-ci.org/nucypher/pyUmbral

pyUmbral is a 100% python implementation of Umbral using OpenSSL and Cryptography.io,
enabling users to perform *split-key proxy-rencryption* and public key encryption
in an understandable and usable manner.

**Alice encrypts data for herself**

.. code-block:: python

    from umbral import umbral, keys

    # Generate a key pair for Alice
    alices_private_key = keys.UmbralPrivateKey.gen_key()
    alices_public_key = private_key.get_pubkey()

    # Encrypt data with bob's public key
    plaintext = b'Proxy Re-encryption is cool!'
    ciphertext, capsule = umbral.encrypt(alices_public_key, plaintext)

    # Decrypt data with Bob's keys
    cleartext = umbral.decrypt(capsule, alices_private_key, ciphertext, alices_public_key)

**Ursula Re-encrypts for Bob**

.. code-block:: python

    # Generate a key pair for Bob
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = private_key.get_pubkey()

    # Bob receives the capsule through a side channel (S3, ipfs, Google Cloud, etc.)
    capsule = capsule

    # Generate split re-encryption keys with "M of N"
    # Minimum threshold of 10 ("M") - and 20 total shares ("N").
    kfrags, _ = umbral.split_rekey(alices_private_key, bobs_public_key, 10, 20)

    # Ursula re-encrypts the shares and bob attaches them to the capsule
    for kfrag in kfrags:
        cfrag = umbral.reencrypt(kfrag, umbral_capsule)
        bob_capsule.attach_cfrag(cfrag)

    # Bob opens the capsule and decrypts the re-encrypted ciphertext
    plaintext = umbral.decrypt(capsule, bobs_private_key, ciphertext, alices_public_key)



Features
==========
- Bulk Data and Key Encapsulation
- Asymmetric Key Pair Generation
- Public Key Encryption & Decryption
- Data Re-encryption
- Re-encryption Key Generation
- Threshold re-encryption key splitting (via Shamir's Secret Sharing)



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


Technical documentation
========================
  "Umbral: A Threshold Proxy Re-Encryption Scheme"
  by David Nuñez

Technical documentation and cryptographic specifications
are availible on GitHub https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf


Support & Contribute
=====================

- Issue Tracker: https://github.com/nucypher/pyUmbral/issues
- Source Code: https://github.com/nucypher/pyUmbral
