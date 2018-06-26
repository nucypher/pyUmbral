==============
Using pyUmbral
==============
.. image:: .static/PRE_image.png


Import umbral modules

.. testsetup::

        import sys
        import os

        sys.path.append(os.path.abspath(os.getcwd()))
        from umbral import pre, keys, config, signing

.. code-block:: python

    from umbral import pre, keys, config, signing


Configuration
==============


Setting the default curve
--------------------------

The best way to start using pyUmbral is to decide on a elliptic curve to use and set it as your default.

.. doctest::
    >>> config._CONFIG.___CONFIG__curve = None
    >>> config._CONFIG.___CONFIG__params = None
    >>> from cryptography.hazmat.primitives.asymmetric import ec
    >>> config.set_default_curve(ec.SECP256K1)

.. code-block:: python

    config.set_default_curve(ec.SECP256K1)


For more information on curves, see :doc:`choosing_and_using_curves`.


Encryption
==========


Generate an Umbral key pair
-----------------------------
First, Let's generate two asymmetric key pairs for Alice:
A delegating key pair and a Signing key pair.

.. doctest::

    >>> alices_private_key = keys.UmbralPrivateKey.gen_key()
    >>> alices_public_key = alices_private_key.get_pubkey()

    >>> alices_signing_key = keys.UmbralPrivateKey.gen_key()
    >>> alices_verifying_key = alices_signing_key.get_pubkey()
    >>> alices_signer = signing.Signer(private_key=alices_signing_key)

.. code-block:: python

    alices_private_key = keys.UmbralPrivateKey.gen_key()
    alices_public_key = alices_private_key.get_pubkey()

    alices_signing_key = keys.UmbralPrivateKey.gen_key()
    alices_verifying_key = alices_signing_key.get_pubkey()
    alices_signer = signing.Signer(private_key=alices_signing_key)


Encrypt with a public key
--------------------------
Now let's encrypt data with Alice's public key.
Invocation of `umbral.encrypt` returns both the `ciphertext`,
and a `capsule`, Anyone with Alice's public key can perform
this operation.


.. doctest::

    >>> plaintext = b'Proxy Re-encryption is cool!'
    >>> ciphertext, capsule = pre.encrypt(alices_public_key, plaintext)

.. code-block:: python

    plaintext = b'Proxy Re-encryption is cool!'
    ciphertext, capsule = pre.encrypt(alices_public_key, plaintext)


Decrypt with a private key
---------------------------
Since data was encrypted with Alice's public key,
Alice can open the capsule and decrypt the ciphertext with her private key.

.. doctest::

    >>> cleartext = pre.decrypt(ciphertext=ciphertext, capsule=capsule, decrypting_key=alices_private_key)

.. code-block:: python

    cleartext = pre.decrypt(ciphertext=ciphertext, capsule=capsule,
                            decrypting_key=alices_private_key)


Threshold split-key re-encryption
==================================

Bob Exists
-----------

.. doctest::

    >>> bobs_private_key = keys.UmbralPrivateKey.gen_key()
    >>> bobs_public_key = bobs_private_key.get_pubkey()


.. code-block:: python

    # Generate umbral keys for Bob.
    bobs_private_key = keys.UmbralPrivateKey.gen_key()
    bobs_public_key = bobs_private_key.get_pubkey()


Alice grants access to Bob by generating kfrags 
-----------------------------------------------
When Alice wants to grant Bob access to open her encrypted messages, 
she creates *threshold split re-encryption keys*, or *"kfrags"*, 
which are next sent to N proxies or *Ursulas*. 

| Generate re-encryption key fragments with "`M` of `N`":
| `M` - Minimum threshold of key fragments needed to activate a capsule.
| `N` - Total number of key fragments to generate.

.. doctest::

    >>> kfrags = pre.split_rekey(delegating_privkey=alices_private_key, signer=alices_signer, receiving_pubkey=bobs_public_key, threshold=10, N=20)


.. code-block:: python

   kfrags = pre.split_rekey(delegating_privkey=alices_private_key,
                            signer=alices_signer,
                            receiving_pubkey=bobs_public_key,
                            threshold=10,
                            N=20)

Bob receives a capsule
-----------------------
Next, let's generate a key pair for Bob, and pretend to send
him the capsule through a side channel like
S3, IPFS, Google Cloud, Sneakernet, etc.

.. code-block:: python

   # Bob receives the capsule through a side-channel
   capsule = capsule


Bob fails to open the capsule
-------------------------------
If Bob attempts to open a capsule that was not encrypted for his public key,
or re-encrypted for him by Ursula, he will not be able to open it.


.. code-block:: python

  try:
      fail = pre.decrypt(ciphertext=ciphertext, capsule=capsule, decrypting_key=bobs_private_key)
  except:
      print("Decryption failed!")


Ursulas perform re-encryption
------------------------------
Bob asks several Ursulas to re-encrypt the capsule so he can open it. 
Each Ursula performs re-encryption on the capsule using the `kfrag` 
provided by Alice, obtaining this way a "capsule fragment", or `cfrag`,
Let's mock a network or transport layer by sampling `M` random `kfrags`,
one for each required Ursula.

Bob collects the resulting `cfrags` from several Ursulas. 
Bob must gather at least `M` `cfrags` in order to activate the capsule.


.. doctest::

    >>> import random
    >>> kfrags = random.sample(kfrags, 10)

    >>> cfrags = list()
    >>> for kfrag in kfrags:
    ...     cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
    ...     cfrags.append(cfrag)

    >>> assert len(cfrags) == 10


.. code-block:: python

    import random

    kfrags = random.sample(kfrags,    # All kfrags from above
                           10)        # M - Threshold

    cfrags = list()                   # Bob's cfrag collection
    for kfrag in kfrags:
      cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
      cfrags.append(cfrag)            # Bob collects a cfrag


Bob attaches cfrags to the capsule
----------------------------------
Bob attaches at least `M` `cfrags` to the capsule;
Then it can become *activated*.

.. doctest::
    >>> capsule.set_correctness_keys(delegating=alices_public_key, receiving=bobs_public_key, verifying=alices_verifying_key)
    (True, True, True)
    >>> for cfrag in cfrags:
    ...     capsule.attach_cfrag(cfrag)

.. code-block:: python

   capsule.set_correctness_keys(delegating=alices_public_key, receiving=bobs_public_key, verifying=alices_verifying_key)

   for cfrag in cfrags:
       capsule.attach_cfrag(cfrag)


Bob activates and opens the capsule
------------------------------------
Finally, Bob activates and opens the capsule,
then decrypts the re-encrypted ciphertext.

.. doctest::

    >>> capsule.set_correctness_keys(delegating=alices_public_key, receiving=bobs_public_key, verifying=alices_verifying_key)
    (True, True, True)
    >>> for cfrag in cfrags:
    ...     capsule.attach_cfrag(cfrag)
    >>> cleartext = pre.decrypt(ciphertext=ciphertext, capsule=capsule, decrypting_key=bobs_private_key)
    >>> assert cleartext == plaintext


.. code-block:: python

   cleartext = pre.decrypt(ciphertext=ciphertext,
                           capsule=capsule,
                           decrypting_key=bobs_private_key)
