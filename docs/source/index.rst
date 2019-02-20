.. pyUmbral documentation master file
   created Thu Feb 15 12:47:25 2018.

========
pyUmbral
========
.. start-badges

|version|  |circleci| |commits-since| |docs| |discord|

.. |docs| image:: https://readthedocs.org/projects/pyumbral/badge/?style=flat
    :target: https://readthedocs.org/projects/pyumbral
    :alt: Documentation Status

.. |discord| image:: https://img.shields.io/discord/411401661714792449.svg?logo=discord
    :target: https://discord.gg/xYqyEby
    :alt: Discord

.. |circleci| image:: https://img.shields.io/circleci/project/github/nucypher/pyUmbral.svg?logo=circleci
    :target: https://circleci.com/gh/nucypher/pyUmbral/tree/master
    :alt: CircleCI build status

.. |version| image:: https://img.shields.io/pypi/v/umbral.svg
    :alt: PyPI Package latest release
    :target: https://pypi.org/project/umbral

.. |commits-since| image:: https://img.shields.io/github/commits-since/nucypher/pyumbral/v0.1.3-alpha.0.svg
    :alt: Commits since latest release
    :target: https://github.com/nucypher/pyUmbral/compare/v0.1.3-alpha.0...master

.. end-badges

pyUmbral is a Python implementation of David Nuñez's threshold proxy re-encryption scheme: Umbral_.
Implemented with OpenSSL_ and Cryptography.io_, pyUmbral is a referential and open-source cryptography library
extending the traditional cryptological narrative of "Alice and Bob" by introducing a new actor,
*Ursula*, who has the ability to take secrets encrypted for Alice and *re-encrypt* them for Bob,
without being able to learn any information about the original secret.

pyUmbral is the cryptographic engine behind nucypher_,
a proxy re-encryption network to empower privacy in decentralized systems.

.. _Umbral: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
.. _Cryptography.io: https://cryptography.io/en/latest/
.. _OpenSSL: https://www.openssl.org/
.. _nucypher: https://github.com/nucypher/nucypher

.. toctree::
   :maxdepth: 3
   :caption: Table of Contents:

   installation
   using_pyumbral


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


Indices and Tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
