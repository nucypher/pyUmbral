Public API
==========

.. automodule:: umbral

Keys
----

.. autoclass:: SecretKey()
    :members:
    :show-inheritance:

.. autoclass:: PublicKey()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: SecretKeyFactory()
    :members:
    :show-inheritance:

.. autoclass:: Signer
    :members:

.. autoclass:: Signature()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

Intermediate objects
--------------------

.. autoclass:: Capsule()
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: KeyFrag()
    :members: verify
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: VerifiedKeyFrag()
    :members:
    :special-members: __eq__, __hash__

.. autoclass:: CapsuleFrag()
    :members:
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: VerifiedCapsuleFrag()
    :special-members: __eq__, __hash__

Encryption, re-encryption and decryption
----------------------------------------

.. autofunction:: encrypt

.. autofunction:: decrypt_original

.. autofunction:: generate_kfrags

.. autofunction:: reencrypt

.. autofunction:: decrypt_reencrypted

Utilities
---------

.. autoclass:: umbral.GenericError
    :show-inheritance:

.. autoclass:: umbral.VerificationError
    :show-inheritance:

.. autoclass:: umbral.serializable.Serializable
    :members: from_bytes
    :special-members: __bytes__
