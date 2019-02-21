.. pyUmbral documentation master file
   created Thu Feb 15 12:47:25 2018.

========
pyUmbral
========
v0.1.3-alpha.0

.. image:: https://circleci.com/gh/nucypher/pyUmbral/tree/master.svg?style=svg
    :target: https://circleci.com/gh/nucypher/pyUmbral/tree/master

pyUmbral is a python implementation of David Nuñez's threshold proxy rencryption scheme: Umbral_.
Implemented with OpenSSL_ and Cryptography.io_, pyUmbral is a referential and open-source cryptography library
extending the traditional cryptological narrative of "Alice and Bob" by introducing a new actor,
*Ursula*, who has the ability to take secrets encrypted for Alice and *re-encrypt* them for Bob.

.. _Umbral: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
.. _Cryptography.io: https://cryptography.io/en/latest/
.. _OpenSSL: https://www.openssl.org/

.. toctree::
   :maxdepth: 3
   :caption: Table of Contents:

   installation
   using_pyumbral


Features
==========
- Re-encryption Toolkit
- Re-encryption Key Fragmentation
- Key Encapsulation
- Elliptic Curve Arithmetic


Academic Whitepaper
====================

The Umbral scheme academic whitepaper and cryptographic specifications
are availible on GitHub_.

  "Umbral A Threshold Proxy Re-Encryption Scheme"
  *by David Nuñez*
  https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

.. _GitHub: https://github.com/nucypher/umbral-doc/


Support & Contribute
=====================

- Issue Tracker: https://github.com/nucypher/pyUmbral/issues
- Source Code: https://github.com/nucypher/pyUmbral


Security
========

If you identify vulnerabilities with _any_ nucypher code,
please email security@nucypher.com with relevant information to your findings.
We will work with researchers to coordinate vulnerability disclosure between our partners
and users to ensure successful mitigation of vulnerabilities.

Throughout the reporting process,
we expect researchers to honor an embargo period that may vary depending on the severity of the disclosure.
This ensures that we have the opportunity to fix any issues, identify further issues (if any), and inform our users.

Sometimes vulnerabilities are of a more sensitive nature and require extra precautions.
We are happy to work together to use a more secure medium, such as Signal.
Email security@nucypher.com and we will coordinate a communication channel that we're both comfortable with.


Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
