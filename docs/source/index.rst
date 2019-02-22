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

.. |commits-since| image:: https://img.shields.io/github/commits-since/nucypher/pyumbral/v0.1.3-alpha.1.svg
    :alt: Commits since latest release
    :target: https://github.com/nucypher/pyUmbral/compare/v0.1.3-alpha.1...master

.. end-badges

pyUmbral is the reference implementation of the Umbral_ threshold proxy re-encryption scheme.
It is open-source, built with Python, and uses OpenSSL_ and Cryptography.io_.

Using Umbral, Alice (the data owner) can *delegate decryption rights* to Bob for
any ciphertext intended to her, through a re-encryption process performed by a
set of semi-trusted proxies or *Ursulas*. When a threshold of these proxies
participate by performing re-encryption, Bob is able to combine these independent
re-encryptions and decrypt the original message using his private key.

.. image:: https://www.nucypher.com/_next/static/images/umbral-d60f22230f2ac92b56c6e7d84794e5c4.svg
  :width: 400 px
  :align: center

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
are available on GitHub_.

  "Umbral: A Threshold Proxy Re-Encryption Scheme"
  *by David Nuñez*.
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
