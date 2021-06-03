==============
Using pyUmbral
==============

.. image:: .static/PRE_image.png


.. testsetup:: capsule_story

    import sys
    import os
    sys.path.append(os.path.abspath(os.getcwd()))


Elliptic Curves
===============

The matter of which curve to use is the subject of some debate.  If you aren't sure, you might start here:
https://safecurves.cr.yp.to/

A number of curves are available in the Cryptography.io_ library, on which pyUmbral depends.
You can find them in the ``cryptography.hazmat.primitives.asymmetric.ec`` module.

.. _Cryptography.io: https://cryptography.io/en/latest/

.. important::

    Be careful when choosing a curve - the security of your application depends on it.

We provide curve ``SECP256K1`` as a default because it is the basis for a number of crypto-blockchain projects;
we don't otherwise endorse its security.
We additionally support curves ``SECP256R1`` (also known as "NIST P-256") and ``SECP384R1`` ("NIST P-384"), but they cannot currently be selected via the public API.


Encryption
==========


Generate an Umbral key pair
-----------------------------
First, let's generate two asymmetric key pairs for Alice:
A delegating key pair and a signing key pair.

.. doctest:: capsule_story

    >>> from umbral import SecretKey, PublicKey, Signer

    >>> alices_secret_key = SecretKey.random()
    >>> alices_public_key = PublicKey.from_secret_key(alices_secret_key)

    >>> alices_signing_key = SecretKey.random()
    >>> alices_verifying_key = PublicKey.from_secret_key(alices_signing_key)
    >>> alices_signer = Signer(alices_signing_key)


Encrypt with a public key
--------------------------
Now let's encrypt data with Alice's public key.
Invocation of :py:func:`encrypt` returns both a ``capsule`` and a ``ciphertext``.
Note that anyone with Alice's public key can perform this operation.


.. doctest:: capsule_story

    >>> from umbral import encrypt
    >>> plaintext = b'Proxy Re-encryption is cool!'
    >>> capsule, ciphertext = encrypt(alices_public_key, plaintext)


Decrypt with a private key
---------------------------
Since data was encrypted with Alice's public key,
Alice can open the capsule and decrypt the ciphertext with her private key.

.. doctest:: capsule_story

    >>> from umbral import decrypt_original
    >>> cleartext = decrypt_original(alices_secret_key, capsule, ciphertext)


Threshold Re-Encryption
==================================

Bob Exists
-----------

.. doctest:: capsule_story

    >>> bobs_secret_key = SecretKey.random()
    >>> bobs_public_key = PublicKey.from_secret_key(bobs_secret_key)


Alice grants access to Bob by generating kfrags
-----------------------------------------------
When Alice wants to grant Bob access to view her encrypted data,
she creates *re-encryption key fragments*, or *"kfrags"*,
which are next sent to N proxies or *Ursulas*.

Alice must specify ``num_kfrags`` (the total number of kfrags),
and a ``threshold`` (the minimum number of kfrags needed to activate a capsule).
In the following example, Alice creates 20 kfrags,
but Bob needs to get only 10 re-encryptions to activate the capsule.

.. doctest:: capsule_story

    >>> from umbral import generate_kfrags
    >>> kfrags = generate_kfrags(delegating_sk=alices_secret_key,
    ...                          receiving_pk=bobs_public_key,
    ...                          signer=alices_signer,
    ...                          threshold=10,
    ...                          num_kfrags=20)


Bob receives a capsule
-----------------------
Next, let's generate a key pair for Bob, and pretend to send
him the capsule through a side channel like
S3, IPFS, Google Cloud, Sneakernet, etc.

.. code-block:: python

   # Bob receives the capsule through a side-channel: IPFS, Sneakernet, etc.
   capsule = <fetch the capsule through a side-channel>


Bob fails to open the capsule
-------------------------------
If Bob attempts to open a capsule that was not encrypted for his public key,
or re-encrypted for him by Ursula, he will not be able to open it.

.. doctest:: capsule_story

    >>> fail = decrypt_original(delegating_sk=bobs_secret_key,
    ...                         capsule=capsule,
    ...                         ciphertext=ciphertext)
    Traceback (most recent call last):
        ...
    umbral.GenericError


Ursulas perform re-encryption
------------------------------
Bob asks several Ursulas to re-encrypt the capsule so he can open it.
Each Ursula performs re-encryption on the capsule using the ``kfrag``
provided by Alice, obtaining this way a "capsule fragment", or ``cfrag``.
Let's mock a network or transport layer by sampling ``threshold`` random kfrags,
one for each required Ursula.

Bob collects the resulting cfrags from several Ursulas.
Bob must gather at least ``threshold`` cfrags in order to open the capsule.


.. doctest:: capsule_story

    >>> import random
    >>> kfrags = random.sample(kfrags,  # All kfrags from above
    ...                        10)      # M - Threshold

    >>> from umbral import reencrypt
    >>> cfrags = list()                 # Bob's cfrag collection
    >>> for kfrag in kfrags:
    ...     cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
    ...     cfrags.append(cfrag)        # Bob collects a cfrag

.. doctest:: capsule_story
   :hide:

    >>> assert len(cfrags) == 10


Decryption
==================================

Bob checks the capsule fragments
--------------------------------
If Bob received the capsule fragments in serialized form,
he can verify that they are valid and really originate from Alice,
using Alice's public keys.

.. doctest:: capsule_story

    >>> from umbral import CapsuleFrag
    >>> suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags]
    >>> cfrags = [cfrag.verify(capsule,
    ...                        verifying_pk=alices_verifying_key,
    ...                        delegating_pk=alices_public_key,
    ...                        receiving_pk=bobs_public_key,
    ...                        )
    ...           for cfrag in suspicious_cfrags]


Bob opens the capsule
---------------------
Finally, Bob decrypts the re-encrypted ciphertext using his key.

.. doctest:: capsule_story

    >>> from umbral import decrypt_reencrypted
    >>> cleartext = decrypt_reencrypted(receiving_sk=bobs_secret_key,
    ...                                 delegating_pk=alices_public_key,
    ...                                 capsule=capsule,
    ...                                 verified_cfrags=cfrags,
    ...                                 ciphertext=ciphertext)


.. doctest:: capsule_story
   :hide:

    >>> assert cleartext == plaintext
