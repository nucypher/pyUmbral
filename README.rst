.. role:: bash(code)
   :language: bash

=========
pyUmbral
=========
v0.1.0-alpha.2

.. image:: https://circleci.com/gh/nucypher/pyUmbral/tree/master.svg?style=svg
    :target: https://circleci.com/gh/nucypher/pyUmbral/tree/master

pyUmbral is a python implementation of David Nuñez's threshold proxy re-encryption scheme: Umbral_.
Implemented with OpenSSL_ and Cryptography.io_, pyUmbral is a referential and open-source cryptography library
extending the traditional cryptological narrative of "Alice and Bob" by introducing a new actor,
*Ursula*, who has the ability to take secrets encrypted for Alice and *re-encrypt* them for Bob.

.. _Umbral: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
.. _Cryptography.io: https://cryptography.io/en/latest/
.. _OpenSSL: https://www.openssl.org/

Usage
=====

**Key Generation**

.. code-block:: python

    from umbral import pre, keys, signing

    # Generate Umbral keys for Alice.
    alices_private_key = keys.UmbralPrivateKey.gen_key()
    alices_public_key = alices_private_key.get_pubkey()

    alices_signing_key = keys.UmbralPrivateKey.gen_key()
    alices_verifying_key = alices_signing_key.get_pubkey()
    alices_signer = signing.Signer(private_key=alices_signing_key)

    # Generate Umbral keys for Bob.
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = bobs_private_key.get_pubkey()


**Encryption**

.. code-block:: python

    # Encrypt data with Alice's public key.
    plaintext = b'Proxy Re-encryption is cool!'
    ciphertext, capsule = pre.encrypt(alices_public_key, plaintext)

    # Decrypt data with Alice's private key.
    cleartext = pre.decrypt(ciphertext=ciphertext, 
                            capsule=capsule, 
                            decrypting_key=alices_private_key)


**Split Re-Encryption Keys**

.. code-block:: python

    # Alice generates "M of N" split re-encryption keys for Bob. 
    # In this example, 10 out of 20.
    kfrags = pre.split_rekey(delegating_privkey=alices_private_key,
                             signer=alices_signer,
                             receiving_pubkey=bobs_public_key,
                             threshold=10,
                             N=20)


**Re-Encryption**

.. code-block:: python

  # Several Ursulas perform re-encryption, and Bob collects the resulting `cfrags`.
  # He must gather at least `threshold` `cfrags` in order to activate the capsule.

  capsule.set_correctness_keys(delegating=alices_public_key,
                               receiving=bobs_public_key,
                               verifying=alices_verifying_key)

  cfrags = list()           # Bob's cfrag collection
  for kfrag in kfrags[:10]:
    cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
    cfrags.append(cfrag)    # Bob collects a cfrag


**Decryption by Bob**

.. code-block:: python

  # Bob activates and opens the capsule
  for cfrag in cfrags:
    capsule.attach_cfrag(cfrag)

  bob_cleartext = pre.decrypt(ciphertext=ciphertext, 
                              capsule=capsule, 
                              decrypting_key=bobs_private_key)
  assert bob_cleartext == plaintext

See more detailed usage examples in the docs_ directory.

.. _docs : https://github.com/nucypher/pyUmbral/tree/master/docs


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

OFAC Sanctions Disclaimer
=========================

By using this software, you hereby affirm you are not an individual or entity subject to economic sanctions administered by the U.S. Government or any other applicable authority, including but not limited to, sanctioned party lists administered by the U.S. Treasury Department’s Office of Foreign Assets Control (OFAC), the U.S. State Department, and the U.S. Commerce Department.  You further affirm you are not located in, or ordinarily resident in, any country, territory or region subject to comprehensive economic sanctions administered by OFAC, which are subject to change but currently include Cuba, Iran, North Korea, Syria and the Crimea region.
