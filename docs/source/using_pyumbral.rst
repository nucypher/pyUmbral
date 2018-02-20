==============
Using pyUmbral
==============
.. image:: .static/PRE_image.png


Import umbral modules:

.. code-block:: python

  from umbral import umbral, keys, config


Configuration
==============

Setting the default curve
--------------------------

PyUmbral uses dependency injection internally to pass elliptic curve context.
This allows flexibility with regard to pyUmbral's ability to peform
elliptic curve operations and re-encryption with alternate curve specifications.

If a default curve is not manually specified, SECP256K1 will be used with the caveat of
a small net performace loss, and the raising of a `RuntimeWarning`.

.. code-block:: python

  keys.UmbralPrivateKey.gen_key()
  RuntimeWarning: No default curve has been set.  Using SECP256K1.  A slight performance penalty has been incurred for only this call.  Set a default curve with umbral.config.set_default_curve().


To silence the warning, configure pyUmbral by invoking `umbral.config.set_default_curve`.

To configure pyUmbral to use the default curve (SECP256K1):

.. code-block:: python

    config.set_default_curve()

Attempting to set the default curve twice in the same runtime will raise
a `UmbralConfigurationError`.

.. code-block:: python

  config.set_default_curve()
  Traceback (most recent call last):
  ...
  umbral.config.UmbralConfigurationError: You can only set the default curve once.  Do it once and then leave it alone.


Public Key Encryption
======================


Generate an umbral key pair
-----------------------------
Let's generate an asymmetric key pair for Alice.

.. code-block:: python

  alices_private_key = keys.UmbralPrivateKey.gen_key()
  alices_public_key = private_key.get_pubkey()


Encrypt with a public key
-------------------------------
.. code-block:: python

  plaintext = b'Proxy Re-encryption is cool!'
  ciphertext, capsule = umbral.encrypt(alices_public_key,
                                       plaintext)


Decrypt with a private key
--------------------------------
.. code-block:: python

    cleartext = umbral.decrypt(capsule, alices_private_key,
                               ciphertext, alices_public_key)


Split key re-encryption
=========================
Let's generate a key pair for Bob, and pretend to send send him the capsule
through a side channel like S3, ipfs, Google Cloud, etc.

.. code-block:: python

   # Generate a key pair for Bob
   bobs_private_key = keys.UmbralPrivateKey.gen_key()
   bobs_public_key = private_key.get_pubkey()

   # Bob receives the capsule
   capsule = <fetch a capsule through side channel>


Bob fails to open the capsule
----------------------------------

.. code-block:: python

  try:
      fail = umbral.decrypt(capsule,
                            bobs_private_key,
                            ciphertext,
                            alices_public_key)
  except:
      print("Decryption failed!")


Alice generates re-encryption keys for Bob
--------------------------------------------
When Alice wants to send a re-encrypted message to bob,
*threshold split re-encryption keys* can be distributed,
and reconstructed with Shamir's Secret Sharing.

| Generate split re-encryption keys with "`M` of `N`":
| A minimum threshold of 10 ("M") - and 20 total shares ("N").

.. code-block:: python

   kfrags, _ = umbral.split_rekey(alices_private_key,
                                  bobs_public_key,
                                  10,    # M - Threshold
                                  20)    # N - Total


Bob gathers re-encryption key fragments (kfrags)
-------------------------------------------------
Bob gathers at least `M` re-encryption key fragments or "kfrags".
Let's mock a network  or transport layer by sampling `M` random `kfrags`.

.. code-block:: python

    import random

    kfrags = random.sample(kfrags,    # All kfrags from above
                           10)        # M - Threshold



Ursula performs re-encryption
------------------------------
After Bob gathers at leats `M` re-encryption keys, He presents them to Ursula,
a proxy re-encryption actor.

Ursula exchanges `kfrags` for `cfrags` with Bob,
altering the state of the `capsule`. Bob collects the resulting `cfrags` from Ursula.

.. code-block:: python

   cfrags = []                 # Bob's cfrag collection
   for kfrag in kfrags:
       cfrag = umbral.reencrypt(kfrag, capsule)
       cfrags.append(cfrag)    # Bob collects the cfrags


Bob attches cfrags to the capsule
----------------------------------
Bob attaches at least `M` `cfrags` to the capsule. Then the capsule
can be *activated*.

.. code-block:: python

   for cfrag in cfrags:
       capsule.attach_cfrag(cfrag)


Bob opens the capsule
------------------------
Bob activates the capsule, opens it, and decrypts the re-encrypted ciphertext,
revealing the message.

.. code-block:: python

   cleartext = umbral.decrypt(capsule, bobs_private_key,
                              ciphertext, alices_public_key)
