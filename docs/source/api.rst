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

Intermediate objects
--------------------

.. autoclass:: Capsule()
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: KeyFrag()
    :members: verify
    :special-members: __eq__, __hash__
    :show-inheritance:

.. autoclass:: CapsuleFrag()
    :members: verify
    :special-members: __eq__, __hash__
    :show-inheritance:

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

.. autoclass:: umbral.serializable.Serializable
    :members: from_bytes
    :special-members: __bytes__
