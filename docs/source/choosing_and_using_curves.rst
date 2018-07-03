=========================
Choosing and Using Curves
=========================


The matter of which curve to use is the subject of some debate.  If you aren't sure, you might start here:
https://safecurves.cr.yp.to/

A number of curves are available in the python cryptography library, on which pyumbral depends.
You can find them in cryptography.hazmat.primitives.asymmetric.ec.

Be careful when choosing a curve - the security of your application depends on it.

We provide SECP256K1 as a default because it is the basis for a number of crypto-blockchain projects;
we don't otherwise endorse its security.


Setting a default curve
--------------------------

Before you perform any ECC operations, you can set a default curve.

.. code-block:: python

    >>> from cryptography.hazmat.primitives.asymmetric import ec
    >>> config.set_default_curve(ec.SECP256K1)

If you don't set a default curve, then SECP256K1 will be set for you when you perform the first ECC
operation.  This causes a small one-time performance penalty.


.. code-block:: python

    >>> from umbral import keys
    >>> private_key = keys.UmbralPrivateKey.gen_key()

    RuntimeWarning: No default curve has been set.  Using SECP256K1.
    A slight performance penalty has been incurred for only this call.
    Set a default curve with umbral.config.set_default_curve().


To use SECP256K1 and avoid this penalty, you can simply call `set_default_curve()` with no argument:


.. code-block:: python

    >>> config.set_default_curve()

Attempting to set the default curve twice in the same runtime will raise
a `UmbralConfigurationError`.


.. code-block:: python

    >>> from umbral import config
    >>> config.set_default_curve()
    >>> config.set_default_curve()
    Traceback (most recent call last):
        ...
    umbral.config._CONFIG.UmbralConfigurationError
