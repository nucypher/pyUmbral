.. pyUmbral documentation master file
   created Thu Feb 15 12:47:25 2018.

pyUmbral
========

.. image:: https://travis-ci.org/nucypher/pyUmbral.svg?branch=master
   :target: https://travis-ci.org/nucypher/pyUmbral

pyUmbral is a 100% python implementation of Umbral using OpenSSL and Cryptography.io,
enabling users to perform *split-key proxy re-encryption* and public key encryption
in an understandable and usable manner.

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents:

   installation


Features
=========
- Bulk Data and Key Encapsulation
- Asymmetric Key Pair Generation
- Public Key Encryption & Decryption
- Data Re-encryption
- Re-encryption Key Generation
- Threshold re-encryption key splitting (via Shamir's Secret Sharing)


Technical documentation
========================
  "Umbral: A Threshold Proxy Re-Encryption Scheme"
  by David Nuñez

Technical documentation and cryptographic specifications
are availible on GitHub https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf.


Support & Contribute
=====================

- Issue Tracker: https://github.com/nucypher/pyUmbral/issues
- Source Code: https://github.com/nucypher/pyUmbral



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
