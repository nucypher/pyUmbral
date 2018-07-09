"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import os
from distutils.core import setup


BASE_DIR = os.path.dirname(__file__)

ABOUT = dict()
with open(os.path.join(BASE_DIR, "umbral", "__about__.py")) as f:
    exec(f.read(), ABOUT)


with open(os.path.join(BASE_DIR, "README.rst")) as f:
    long_description = f.read()


DEPENDENCY_LINKS = ["http://github.com/nucypher/bytestringSplitter/tarball/master#egg=byteStringSplitter-0.0.1",
                    # "./wheelhouse/cryptography-2.3.dev1-cp35-cp35m-linux_x86_64.whl",
                    # "./wheelhouse/cryptography-2.3.dev1-cp36-cp36m-linux_x86_64.whl",
                    # "./wheelhouse/cryptography-2.3.dev1-cp37-cp37m-linux_x86_64.whl",
                    # "./wheelhouse/cryptography-2.3.dev1-cp36-cp36m-macosx_10_13_x86_64.whl",
                    ]

INSTALL_REQUIRES = [
                    # 'byteStringSplitter==0.0.1',
                    'pynacl',
                    'idna>=2.1',
                    'asn1crypto>=0.21.0',
                    'six>=1.4.1',
                    'cffi>=1.7']

EXTRAS_REQUIRE = {'testing': ['bumpversion',
                              'pytest',
                              'pytest-cov',
                              'pytest-mypy',
                              'pytest-mock',
                              'mock',
                              'coverage',
                              'codecov',
                              'monkeytype==18.2.0'],

                  'docs': ['sphinx', 'sphinx-autobuild'],

                  'benchmarks': ['pytest-benchmark'],
                  }


setup(name=ABOUT['__title__'],
      version=ABOUT['__version__'],
      author=ABOUT['__author__'],
      description=ABOUT['__summary__'],
      long_description=long_description,

      dependency_links=DEPENDENCY_LINKS,
      extras_require=EXTRAS_REQUIRE,
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'],

      classifiers=[
          "Development Status :: 2 - Pre-Alpha",
          "Intended Audience :: Science/Research",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Natural Language :: English",
          "Programming Language :: Python :: Implementation",
          "Programming Language :: Python :: 3 :: Only",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Topic :: Scientific/Engineering",
        ]
      )
